/**
 * Cloudflare Worker — Universal CRUD API
 * Prinsip: Modular · DRY · Reuse · Scalable · Zero Dependency
 * Auth   : HMAC-SHA256 token (JWT-like, tanpa library)
 * DB     : Cloudflare D1
 * Output : JSON
 *
 * Routing pattern:
 *   POST   /auth/login          → dapat token
 *   GET    /:table              → list semua baris
 *   GET    /:table/:id          → satu baris
 *   POST   /:table              → insert baris baru
 *   PUT    /:table/:id          → update baris
 *   DELETE /:table/:id          → hapus baris
 *
 * Config wajib di wrangler.toml:
 *   [vars]
 *   JWT_SECRET   = "ganti-dengan-secret-kuat"
 *   ALLOWED_TABLES = "users,products,orders"   ← whitelist tabel
 *
 *   [[d1_databases]]
 *   binding = "DB"
 *   database_name = "nama-db-kamu"
 *   database_id   = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 */

// ─────────────────────────────────────────────
// 1. UTILITAS RESPONSE
// ─────────────────────────────────────────────

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });

const ok      = (data, meta = {})  => json({ ok: true,  data, ...meta });
const err     = (msg,  status = 400) => json({ ok: false, error: msg }, status);
const noAuth  = ()                  => err("Unauthorized", 401);
const notFound = (msg = "Not found") => err(msg, 404);

// ─────────────────────────────────────────────
// 2. HMAC-SHA256 TOKEN (JWT-like, zero dep)
// ─────────────────────────────────────────────

const encoder = new TextEncoder();

async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function createToken(payload, secret, ttlSeconds = 86400) {
  const header  = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body    = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds }));
  const sig     = await hmacSign(secret, `${header}.${body}`);
  return `${header}.${body}.${sig}`;
}

async function verifyToken(token, secret) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const expected = await hmacSign(secret, `${header}.${body}`);
  if (sig !== expected) return null;
  const payload = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/")));
  if (payload.exp < Math.floor(Date.now() / 1000)) return null; // expired
  return payload;
}

const b64url = (str) =>
  btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

// ─────────────────────────────────────────────
// 3. MIDDLEWARE: AUTH
// ─────────────────────────────────────────────

async function authenticate(request, secret) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  return verifyToken(token, secret);
}

// ─────────────────────────────────────────────
// 3b. ROLE GUARD (reuse token payload — Modular · DRY)
// ─────────────────────────────────────────────

function hasRole(user, roles = []) {
  return !!user && roles.includes(user.role);
}

function forbidden() {
  return err("Forbidden — role tidak memiliki akses", 403);
}

// ─────────────────────────────────────────────
// 4. WHITELIST GUARD
// ─────────────────────────────────────────────

function allowedTable(table, env) {
  const tables = (env.ALLOWED_TABLES || "").split(",").map(t => t.trim());
  return tables.includes(table);
}

// ─────────────────────────────────────────────
// 4b. GOOGLE SIGN-IN — VERIFIKASI ID TOKEN
// ─────────────────────────────────────────────
//
// Zero-dependency: memakai endpoint tokeninfo Google (tanpa lib JWT/JWKS).
// Frontend (Google Identity Services) mengirim `credential` (ID token),
// worker ini yang memvalidasi ke server Google lalu menerbitkan token
// internal (HMAC) — client TIDAK PERNAH dipercaya begitu saja.

async function verifyGoogleIdToken(idToken, env) {
  if (!idToken) return null;
  const res = await fetch(
    `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`
  );
  if (!res.ok) return null;
  const payload = await res.json();

  // aud harus cocok dengan Google OAuth Client ID milik aplikasi ini
  if (env.GOOGLE_CLIENT_ID && payload.aud !== env.GOOGLE_CLIENT_ID) return null;
  if (payload.email_verified !== "true" && payload.email_verified !== true) return null;

  return {
    googleId: payload.sub,
    email:    payload.email,
    name:     payload.name || payload.email,
    picture:  payload.picture || null,
  };
}

/** Tentukan role berdasarkan whitelist email di wrangler.toml (Reuse · Scalable) */
function resolveRole(email, env) {
  const admins      = (env.ADMIN_EMAILS      || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  const instructors = (env.INSTRUCTOR_EMAILS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  const e = (email || "").toLowerCase();
  if (admins.includes(e))      return "admin";
  if (instructors.includes(e)) return "instruktur";
  return "peserta";
}

/**
 * PATCH: perbaiki data lama yang `users.id` nya NULL.
 *
 * Root cause: baris user tertentu (mis. dibuat manual lewat D1 Studio
 * sebelum fitur Google Login ada) punya `id = NULL` karena kolom `id`
 * pada tabel lama ternyata bukan alias rowid asli. Akibatnya token JWT
 * dibuat dengan `uid: null`, dan saat enroll query
 * `INSERT INTO enrollments (user_id, ...)` dibind NULL/undefined →
 * melanggar constraint `NOT NULL` → 500 Internal Server Error.
 *
 * Perbaikan: SQLite/D1 tetap punya `rowid` internal yang unik walau
 * kolom `id` kosong. Kalau ketemu baris dengan `id` NULL, isi `id`
 * dengan `rowid` baris itu sendiri (sekali jalan, aman diulang).
 */
async function repairNullUserId(d1, row) {
  if (row.id !== null && row.id !== undefined) return row;
  await d1.prepare(
    `UPDATE users SET id = rowid WHERE rowid = (SELECT rowid FROM users WHERE google_id IS ? AND email = ? LIMIT 1) AND id IS NULL`
  ).bind(row.google_id ?? null, row.email).run();
  const fixed = await d1.prepare(`SELECT * FROM users WHERE email = ? LIMIT 1`).bind(row.email).first();
  return fixed || row;
}

/**
 * Upsert user hasil login Google ke tabel `users` — memakai kembali
 * db.findAll / db.insert / db.update generik (DRY, tanpa query khusus).
 */
async function upsertGoogleUser(d1, profile, env) {
  const existing = await db.findAll(d1, "users", {
    where: { google_id: profile.googleId }, limit: 1,
  });

  if (existing.rows[0]) {
    let row = existing.rows[0];
    row = await repairNullUserId(d1, row); // ⚠️ self-heal data lama yang id-nya NULL
    await db.update(d1, "users", row.id, {
      name: profile.name, picture: profile.picture, last_login: new Date().toISOString(),
    });
    return { ...row, name: profile.name, picture: profile.picture };
  }

  // Cocokkan dengan akun lama berbasis email (mis. dibuat manual admin)
  const byEmail = await db.findAll(d1, "users", { where: { email: profile.email }, limit: 1 });
  if (byEmail.rows[0]) {
    let row = byEmail.rows[0];
    row = await repairNullUserId(d1, row); // ⚠️ self-heal data lama yang id-nya NULL
    await db.update(d1, "users", row.id, {
      google_id: profile.googleId, name: profile.name, picture: profile.picture,
      last_login: new Date().toISOString(),
    });
    return { ...row, google_id: profile.googleId, name: profile.name, picture: profile.picture };
  }

  const role = resolveRole(profile.email, env);
  const newId = await db.insert(d1, "users", {
    google_id: profile.googleId, email: profile.email, name: profile.name,
    picture: profile.picture, role, created_at: new Date().toISOString(),
    last_login: new Date().toISOString(),
  });

  // ⚠️ PATCH PENTING: kolom `id` di tabel `users` lama BUKAN alias rowid
  // asli SQLite (akar masalah yang sama dengan repairNullUserId di atas).
  // db.insert() TIDAK PERNAH menuliskan `id` (kolom itu tidak ada di body
  // insert), jadi kalau baris ini dilewati, kolom `id` di database akan
  // TETAP NULL walau `newId` di memori kelihatan valid. Akibatnya
  // `INSERT INTO enrollments (user_id, ...)` gagal — user_id=newId, tapi
  // di tabel users tidak ada baris ber-id=newId (FK constraint) — 500
  // Internal Server Error persis pada percobaan enroll PERTAMA setelah
  // registrasi baru. Isi manual `id` pakai rowid milik baris yang baru
  // saja dibuat (last_row_id == rowid baris tsb, dijamin SQLite).
  if (newId != null) {
    await d1.prepare(`UPDATE users SET id = ? WHERE rowid = ? AND id IS NULL`)
      .bind(newId, newId).run();
  }

  return { id: newId, ...profile, role };
}

// ─────────────────────────────────────────────
// 5. QUERY BUILDER — GENERIK UNTUK SEMUA TABEL
// ─────────────────────────────────────────────

const db = {
  /** SELECT * FROM :table WHERE id = ? */
  async findOne(d1, table, id) {
    const { results } = await d1.prepare(
      `SELECT * FROM ${table} WHERE id = ? LIMIT 1`
    ).bind(id).all();
    return results[0] ?? null;
  },

  /** SELECT * FROM :table dengan optional filter, sort, pagination */
  async findAll(d1, table, { where = {}, orderBy = "id", dir = "ASC", page = 1, limit = 20 } = {}) {
    const keys   = Object.keys(where);
    const clause = keys.length
      ? "WHERE " + keys.map(k => `${k} = ?`).join(" AND ")
      : "";
    const offset = (Number(page) - 1) * Number(limit);
    const sql    = `SELECT * FROM ${table} ${clause} ORDER BY ${orderBy} ${dir} LIMIT ? OFFSET ?`;
    const vals   = [...Object.values(where), Number(limit), offset];
    const { results } = await d1.prepare(sql).bind(...vals).all();
    const count = await d1.prepare(`SELECT COUNT(*) as n FROM ${table} ${clause}`)
      .bind(...Object.values(where)).first("n");
    return { rows: results, total: count, page: Number(page), limit: Number(limit) };
  },

  /** INSERT INTO :table (cols) VALUES (?) */
  async insert(d1, table, body) {
    const keys   = Object.keys(body);
    const cols   = keys.join(", ");
    const placeh = keys.map(() => "?").join(", ");
    const vals   = Object.values(body);
    const res    = await d1.prepare(
      `INSERT INTO ${table} (${cols}) VALUES (${placeh})`
    ).bind(...vals).run();
    return res.meta?.last_row_id ?? null;
  },

  /** UPDATE :table SET col=? WHERE id=? */
  async update(d1, table, id, body) {
    const keys   = Object.keys(body);
    if (!keys.length) return false;
    const sets   = keys.map(k => `${k} = ?`).join(", ");
    const vals   = [...Object.values(body), id];
    const res    = await d1.prepare(
      `UPDATE ${table} SET ${sets} WHERE id = ?`
    ).bind(...vals).run();
    return res.meta?.changes > 0;
  },

  /** DELETE FROM :table WHERE id=? */
  async remove(d1, table, id) {
    const res = await d1.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(id).run();
    return res.meta?.changes > 0;
  },
};

// ─────────────────────────────────────────────
// 6. ROUTE HANDLER: AUTH
// ─────────────────────────────────────────────

async function handleAuth(request, env) {
  if (request.method !== "POST")
    return err("Method not allowed", 405);

  const body = await request.json().catch(() => ({}));
  const { username, password } = body;

  // ⚠️  Ganti logika ini dengan query D1 ke tabel users kamu
  //     Contoh sederhana: cek env variable saja (untuk demo)
  const validUser = username === env.ADMIN_USER && password === env.ADMIN_PASS;
  if (!validUser) return err("Invalid credentials", 401);

  const token = await createToken({ sub: username, role: "admin" }, env.JWT_SECRET);
  return ok({ token });
}

// ─────────────────────────────────────────────
// 6b. ROUTE HANDLER: LOGIN GOOGLE
// ─────────────────────────────────────────────
//
//   POST /auth/google   body: { credential: "<Google ID token>" }
//   →    { token, user: { id, email, name, picture, role } }

async function handleGoogleAuth(request, env) {
  if (request.method !== "POST") return err("Method not allowed", 405);

  const body = await request.json().catch(() => ({}));
  const profile = await verifyGoogleIdToken(body.credential, env);
  if (!profile) return err("Token Google tidak valid", 401);

  const user  = await upsertGoogleUser(env.DB, profile, env);
  const token = await createToken(
    { uid: user.id, email: user.email, name: user.name, picture: user.picture, role: user.role },
    env.JWT_SECRET
  );

  return ok({
    token,
    user: { id: user.id, email: user.email, name: user.name, picture: user.picture, role: user.role },
  });
}

// ─────────────────────────────────────────────
// 6c. ROUTE HANDLER: PROFIL SENDIRI
// ─────────────────────────────────────────────

async function handleMe(request, env) {
  const user = await authenticate(request, env.JWT_SECRET);
  if (!user) return noAuth();
  return ok({
    uid: user.uid ?? null, sub: user.sub ?? null,
    email: user.email ?? null, name: user.name ?? null,
    picture: user.picture ?? null, role: user.role || "peserta",
  });
}

// ─────────────────────────────────────────────
// 6c. ROUTE HANDLER: ENROLL (pendaftaran peserta ke kursus)
// ─────────────────────────────────────────────
//
//   POST /courses/:slug/enroll   (auth wajib)
//
// SEBELUM patch ini, path `/courses/:id/enroll` TIDAK dikenali router
// (parseRoute hanya tahu /auth, /me, /dashboard, sisanya jatuh ke CRUD
// generik). Akibatnya request ini diperlakukan sebagai
// "POST ke tabel courses dengan id diabaikan" -> body kosong -> 400.
// Handler khusus ini yang benar: cari kursus lewat `slug`, lalu
// INSERT OR IGNORE ke tabel enrollments (idempotent -- klik dua kali
// tidak error, tidak duplikat, karena ada UNIQUE(user_id, course_id)
// di schema.sql).

async function handleEnroll(request, env, slug) {
  const user = await authenticate(request, env.JWT_SECRET);
  if (!user) return noAuth();

  const course = await env.DB.prepare(
    `SELECT id, title, category FROM courses WHERE slug = ? LIMIT 1`
  ).bind(slug).first();

  if (!course) {
    return err(
      `Kursus dengan slug '${slug}' belum ada di database. ` +
      `Jalankan migrasi schema.sql (bagian "seed kursus") dulu.`,
      404
    );
  }

  const uid = user.uid ?? user.sub;
  if (!uid) {
    // Token lama terbit sebelum data user diperbaiki (lihat repairNullUserId).
    // Jangan lanjut insert dengan user_id kosong (akan melanggar NOT NULL
    // dan muncul sebagai 500 yang membingungkan) — minta login ulang saja,
    // karena login berikutnya otomatis memperbaiki id yang NULL.
    return err("Sesi tidak valid (ID pengguna kosong). Silakan logout lalu login ulang dengan Google.", 401);
  }
  await env.DB.prepare(
    `INSERT OR IGNORE INTO enrollments (user_id, course_id) VALUES (?, ?)`
  ).bind(uid, course.id).run();

  return ok({
    enrolled: true,
    courseId: course.id,
    slug,
    title: course.title,
    category: course.category,
  });
}

// ─────────────────────────────────────────────
// 6d. ROUTE HANDLER: PROGRESS (aktivitas modul per peserta)
// ─────────────────────────────────────────────
//
//   POST /courses/:slug/progress   (auth wajib)
//   body: { moduleId: "modul01", completed?: true, score?: number }
//
// Dipanggil frontend (progress-patch.js) setiap kali peserta membuka
// sebuah modul. INSERT ... ON CONFLICT supaya idempotent — dibuka
// berkali-kali tidak membuat baris dobel, cukup update timestamp/skor
// (constraint UNIQUE(user_id, course_id, module_id) sudah ada di
// schema.sql). Ini yang mengisi tabel `progress`, yang sebelumnya jadi
// alasan "Rata-rata Progres per Kursus" & "Progres Belajar Saya" di
// dashboard selalu tampil 0%.

async function handleProgress(request, env, slug) {
  if (request.method !== "POST") return err("Method not allowed", 405);

  const user = await authenticate(request, env.JWT_SECRET);
  if (!user) return noAuth();

  const uid = user.uid ?? user.sub;
  if (!uid) {
    return err("Sesi tidak valid (ID pengguna kosong). Silakan logout lalu login ulang dengan Google.", 401);
  }

  const body      = await request.json().catch(() => ({}));
  const moduleId  = String(body.moduleId || "").trim();
  if (!moduleId) return err("moduleId wajib diisi", 400);

  const completed = body.completed === false ? 0 : 1; // default: aktivitas = selesai dibaca
  const score     = typeof body.score === "number" ? body.score : null;

  const course = await env.DB.prepare(
    `SELECT id, title FROM courses WHERE slug = ? LIMIT 1`
  ).bind(slug).first();
  if (!course) {
    return err(`Kursus dengan slug '${slug}' tidak ditemukan.`, 404);
  }

  // Progres hanya berarti untuk peserta yang benar-benar terdaftar —
  // ini juga mencegah data progres "nyasar" dari orang yang cuma
  // membuka materi tanpa mendaftar (materi OCW memang boleh dibaca
  // publik, tapi progresnya tidak perlu dicatat kalau belum daftar).
  const enrolled = await env.DB.prepare(
    `SELECT id FROM enrollments WHERE user_id = ? AND course_id = ? LIMIT 1`
  ).bind(uid, course.id).first();
  if (!enrolled) {
    return err("Anda belum terdaftar di kursus ini — daftar dulu supaya progres tercatat.", 403);
  }

  const completedAt = completed ? new Date().toISOString() : null;
  await env.DB.prepare(`
    INSERT INTO progress (user_id, course_id, module_id, completed, score, completed_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, course_id, module_id) DO UPDATE SET
      completed    = excluded.completed,
      score        = COALESCE(excluded.score, progress.score),
      completed_at = excluded.completed_at
  `).bind(uid, course.id, moduleId, completed, score, completedAt).run();

  return ok({ tracked: true, courseId: course.id, moduleId, completed: !!completed });
}

// ─────────────────────────────────────────────
// 6d. ROUTE HANDLER: DASHBOARD (privat, role-aware + publik)
// ─────────────────────────────────────────────
//
//   GET /dashboard         (auth) → data berbeda per role
//   GET /dashboard/public  (tanpa auth) → agregat aman untuk halaman umum

async function statsCourses(d1) {
  const { results } = await d1.prepare(`
    SELECT c.id, c.title, c.category,
           COUNT(DISTINCT e.id) AS enrolledCount,
           COUNT(DISTINCT CASE WHEN p.completed = 1 THEN p.id END) AS completedModules,
           COUNT(DISTINCT p.id) AS totalModules
    FROM courses c
    LEFT JOIN enrollments e ON e.course_id = c.id
    LEFT JOIN progress    p ON p.course_id = c.id
    GROUP BY c.id
    ORDER BY enrolledCount DESC
  `).all();
  return results.map(r => ({
    ...r,
    avgProgress: r.totalModules ? Math.round((r.completedModules / r.totalModules) * 100) : 0,
  }));
}

async function handlePublicDashboard(env) {
  const totalPeserta = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM users WHERE role = 'peserta'`
  ).first("n");
  const totalCourses = await env.DB.prepare(`SELECT COUNT(*) AS n FROM courses`).first("n");
  const courses = await statsCourses(env.DB);

  return ok({
    totalPeserta: totalPeserta || 0,
    totalCourses: totalCourses || 0,
    topCourses: courses
      .slice(0, 5)
      .map(c => ({ id: c.id, title: c.title, enrolledCount: c.enrolledCount, avgProgress: c.avgProgress })),
  });
}

async function handlePrivateDashboard(request, env) {
  const user = await authenticate(request, env.JWT_SECRET);
  if (!user) return noAuth();

  // ── ADMIN & INSTRUKTUR: ringkasan seluruh platform ──
  if (hasRole(user, ["admin", "instruktur"])) {
    const totalPeserta = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM users WHERE role = 'peserta'`
    ).first("n");
    const totalInstruktur = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM users WHERE role = 'instruktur'`
    ).first("n");
    const totalCourses = await env.DB.prepare(`SELECT COUNT(*) AS n FROM courses`).first("n");
    const totalEnrollments = await env.DB.prepare(`SELECT COUNT(*) AS n FROM enrollments`).first("n");
    const courses = await statsCourses(env.DB);

    return ok({
      role: user.role,
      summary: {
        totalPeserta: totalPeserta || 0,
        totalInstruktur: totalInstruktur || 0,
        totalCourses: totalCourses || 0,
        totalEnrollments: totalEnrollments || 0,
      },
      topCourses: courses.slice(0, 5),
      allCourses: courses,
    });
  }

  // ── PESERTA: progres belajar milik sendiri ──
  const uid = user.uid ?? user.sub;
  if (!uid) {
    return err("Sesi tidak valid (ID pengguna kosong). Silakan logout lalu login ulang dengan Google.", 401);
  }
  const { results } = await env.DB.prepare(`
    SELECT c.id, c.slug, c.title, c.category,
           COUNT(DISTINCT p.id) AS totalModules,
           COUNT(DISTINCT CASE WHEN p.completed = 1 THEN p.id END) AS doneModules
    FROM enrollments e
    JOIN courses c ON c.id = e.course_id
    LEFT JOIN progress p ON p.course_id = c.id AND p.user_id = e.user_id
    WHERE e.user_id = ?
    GROUP BY c.id
  `).bind(uid).all();

  const myCourses = results.map(r => ({
    ...r,
    progressPct: r.totalModules ? Math.round((r.doneModules / r.totalModules) * 100) : 0,
  }));

  return ok({
    role: user.role,
    summary: {
      totalKursusDiikuti: myCourses.length,
      rataRataProgress: myCourses.length
        ? Math.round(myCourses.reduce((a, c) => a + c.progressPct, 0) / myCourses.length)
        : 0,
    },
    myCourses,
  });
}

// ─────────────────────────────────────────────
// 7. ROUTE HANDLER: CRUD GENERIK
// ─────────────────────────────────────────────

// Tabel yang mengandung data lintas-pengguna (PII/relasi personal) --
// GET mentah lewat CRUD generik hanya boleh admin/instruktur. Peserta
// tetap bisa lihat datanya sendiri lewat /me dan /dashboard yang sudah
// difilter server-side, jadi tidak kehilangan fungsi apa pun.
const SENSITIVE_TABLES = ["users", "enrollments", "progress"];

async function handleCrud(request, env, table, id) {
  if (!allowedTable(table, env))
    return notFound(`Table '${table}' not found`);

  const user = await authenticate(request, env.JWT_SECRET);
  if (!user) return noAuth();

  if (SENSITIVE_TABLES.includes(table) && !hasRole(user, ["admin", "instruktur"])) {
    return forbidden();
  }

  const method = request.method;

  // LIST
  if (method === "GET" && !id) {
    const url    = new URL(request.url);
    const page   = url.searchParams.get("page")    || 1;
    const limit  = url.searchParams.get("limit")   || 20;
    const order  = url.searchParams.get("orderBy") || "id";
    const dir    = (url.searchParams.get("dir") || "ASC").toUpperCase() === "DESC" ? "DESC" : "ASC";
    const result = await db.findAll(env.DB, table, { orderBy: order, dir, page, limit });
    return ok(result.rows, { total: result.total, page: result.page, limit: result.limit });
  }

  // DETAIL
  if (method === "GET" && id) {
    const row = await db.findOne(env.DB, table, id);
    return row ? ok(row) : notFound();
  }

  // CREATE
  if (method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (!Object.keys(body).length) return err("Body tidak boleh kosong");
    const newId = await db.insert(env.DB, table, body);
    return ok({ id: newId }, { status: 201 });
  }

  // UPDATE
  if (method === "PUT" && id) {
    const body    = await request.json().catch(() => ({}));
    const changed = await db.update(env.DB, table, id, body);
    return changed ? ok({ updated: true }) : notFound();
  }

  // DELETE
  if (method === "DELETE" && id) {
    const deleted = await db.remove(env.DB, table, id);
    return deleted ? ok({ deleted: true }) : notFound();
  }

  return err("Method not allowed", 405);
}

// ─────────────────────────────────────────────
// 8. ROUTER UTAMA
// ─────────────────────────────────────────────

function parseRoute(pathname) {
  // /auth/login              → { type: "auth" }
  // /auth/google             → { type: "auth-google" }
  // /me                      → { type: "me" }
  // /dashboard               → { type: "dashboard", scope: "private" }
  // /dashboard/public        → { type: "dashboard", scope: "public" }
  // /courses/:slug/enroll    → { type: "enroll", slug: ":slug" }   ← BARU
  // /products                → { type: "crud", table: "products", id: null }
  // /products/42             → { type: "crud", table: "products", id: "42" }
  const parts = pathname.replace(/^\//, "").split("/");
  if (parts[0] === "auth" && parts[1] === "google") return { type: "auth-google" };
  if (parts[0] === "auth") return { type: "auth" };
  if (parts[0] === "me") return { type: "me" };
  if (parts[0] === "dashboard") return { type: "dashboard", scope: parts[1] === "public" ? "public" : "private" };
  // PENTING: cek pola /courses/:slug/enroll SEBELUM fallback ke CRUD generik,
  // supaya tidak salah kena route { table: "courses", id: ":slug" } yang
  // membuat POST-nya diperlakukan sebagai "insert baris baru ke tabel courses".
  if (parts[0] === "courses" && parts[1] && parts[2] === "enroll") {
    return { type: "enroll", slug: parts[1] };
  }
  // /courses/:slug/progress  → { type: "progress", slug: ":slug" }   ← BARU
  // Sama alasannya dengan /enroll: harus dicek sebelum fallback CRUD generik.
  if (parts[0] === "courses" && parts[1] && parts[2] === "progress") {
    return { type: "progress", slug: parts[1] };
  }
  if (parts[0]) return { type: "crud", table: parts[0], id: parts[1] || null };
  return { type: "unknown" };
}

// ─────────────────────────────────────────────
// 9. CORS HELPER (opsional, aktifkan jika perlu)
// ─────────────────────────────────────────────

function withCors(response) {
  const res = new Response(response.body, response);
  res.headers.set("Access-Control-Allow-Origin", "*");
  res.headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  return res;
}

// ─────────────────────────────────────────────
// 10. ENTRY POINT
// ─────────────────────────────────────────────

export default {
  async fetch(request, env) {
    // Preflight CORS
    if (request.method === "OPTIONS")
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin":  "*",
          "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });

    const url   = new URL(request.url);
    const route = parseRoute(url.pathname);

    let response;
    try {
      if (route.type === "auth")
        response = await handleAuth(request, env);
      else if (route.type === "auth-google")
        response = await handleGoogleAuth(request, env);
      else if (route.type === "me")
        response = await handleMe(request, env);
      else if (route.type === "dashboard")
        response = route.scope === "public"
          ? await handlePublicDashboard(env)
          : await handlePrivateDashboard(request, env);
      else if (route.type === "enroll")
        response = await handleEnroll(request, env, route.slug);
      else if (route.type === "progress")
        response = await handleProgress(request, env, route.slug);
      else if (route.type === "crud")
        response = await handleCrud(request, env, route.table, route.id);
      else
        response = notFound("Endpoint tidak ditemukan");
    } catch (e) {
      console.error(e);
      response = err("Internal server error", 500);
    }

    return withCors(response);
  },
};
