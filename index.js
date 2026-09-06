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
// 4c. VALIDASI URL — dipakai fitur "Pengelolaan Berkas" (materials)
// ─────────────────────────────────────────────
//
// Zero-dependency: regex sederhana, tidak butuh library parsing URL pihak ketiga.

function isHttpUrl(str) {
  try {
    const u = new URL(String(str || ""));
    return u.protocol === "http:" || u.protocol === "https:";
  } catch (e) {
    return false;
  }
}

/** Ekstrak video ID dari berbagai format URL YouTube. null kalau tidak valid. */
function extractYouTubeId(url) {
  if (!isHttpUrl(url)) return null;
  const patterns = [
    /(?:youtube\.com\/watch\?v=)([a-zA-Z0-9_-]{11})/,
    /(?:youtu\.be\/)([a-zA-Z0-9_-]{11})/,
    /(?:youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})/,
    /(?:youtube\.com\/shorts\/)([a-zA-Z0-9_-]{11})/,
  ];
  for (const re of patterns) {
    const m = String(url).match(re);
    if (m) return m[1];
  }
  return null;
}

const MATERIAL_TYPES = ["video", "pdf"];

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
// 6e. ROUTE HANDLER: KUIS (submit hasil kuis per kursus)
// ─────────────────────────────────────────────
//
//   POST /courses/:slug/quiz   (auth wajib)
//   body: { score: number 0-100 }
//
// Frontend (quiz-patch.js) menghitung skor di klien lalu mengirimkannya
// ke sini. Backend TIDAK PERNAH mempercayai status lulus/gagal dari
// klien — status selalu dihitung ulang di server (score >= passing_grade
// milik kursus tsb, lihat schema.sql bagian 9), supaya tidak bisa
// dipalsukan lewat DevTools. Skor TERBAIK peserta disimpan permanen di
// `quiz_results` (UPSERT, idempotent — boleh dikerjakan berkali-kali).
//
// Begitu skor terbaik mencapai passing grade, sertifikat diterbitkan
// OTOMATIS & HANYA SEKALI per (peserta, kursus) lewat
// `INSERT OR IGNORE INTO certificates` (constraint UNIQUE(user_id,
// course_id) mencegah duplikat walau lulus berkali-kali).

function generateCertCode(slug) {
  const year = new Date().getFullYear();
  const rand = crypto.randomUUID().split("-")[0].toUpperCase();
  return `LMS-${slug.toUpperCase()}-${year}-${rand}`;
}

async function handleQuizSubmit(request, env, slug) {
  if (request.method !== "POST") return err("Method not allowed", 405);

  const user = await authenticate(request, env.JWT_SECRET);
  if (!user) return noAuth();

  const uid = user.uid ?? user.sub;
  if (!uid) {
    return err("Sesi tidak valid (ID pengguna kosong). Silakan logout lalu login ulang dengan Google.", 401);
  }

  const body  = await request.json().catch(() => ({}));
  const score = Number(body.score);
  if (!Number.isFinite(score) || score < 0 || score > 100) {
    return err("score wajib berupa angka 0-100", 400);
  }

  const course = await env.DB.prepare(
    `SELECT id, title, category, passing_grade FROM courses WHERE slug = ? LIMIT 1`
  ).bind(slug).first();
  if (!course) return err(`Kursus dengan slug '${slug}' tidak ditemukan.`, 404);

  // Kuis hanya berarti untuk peserta yang benar-benar terdaftar —
  // sama seperti aturan pada handleProgress.
  const enrolled = await env.DB.prepare(
    `SELECT id FROM enrollments WHERE user_id = ? AND course_id = ? LIMIT 1`
  ).bind(uid, course.id).first();
  if (!enrolled) {
    return err("Anda belum terdaftar di kursus ini — daftar dulu supaya kuis dapat dikerjakan.", 403);
  }

  const passingGrade = course.passing_grade || 70;
  const now = new Date().toISOString();

  await env.DB.prepare(`
    INSERT INTO quiz_results (user_id, course_id, best_score, last_score, attempts, status, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
    ON CONFLICT(user_id, course_id) DO UPDATE SET
      last_score = excluded.last_score,
      best_score = MAX(quiz_results.best_score, excluded.last_score),
      attempts   = quiz_results.attempts + 1,
      status     = CASE WHEN MAX(quiz_results.best_score, excluded.last_score) >= ?
                        THEN 'lulus' ELSE 'belum_lulus' END,
      updated_at = excluded.updated_at
  `).bind(
    uid, course.id, score, score, score >= passingGrade ? "lulus" : "belum_lulus", now,
    passingGrade
  ).run();

  const result = await env.DB.prepare(
    `SELECT best_score, last_score, attempts, status FROM quiz_results WHERE user_id = ? AND course_id = ? LIMIT 1`
  ).bind(uid, course.id).first();

  let certificate = null;
  if (result && result.status === "lulus") {
    // Terbitkan sekali saja — kalau sudah ada, ambil yang lama (jangan generate kode baru).
    let cert = await env.DB.prepare(
      `SELECT code, score, issued_at FROM certificates WHERE user_id = ? AND course_id = ? LIMIT 1`
    ).bind(uid, course.id).first();

    if (!cert) {
      const code = generateCertCode(slug);
      await env.DB.prepare(`
        INSERT OR IGNORE INTO certificates (code, user_id, course_id, score, issued_at)
        VALUES (?, ?, ?, ?, ?)
      `).bind(code, uid, course.id, result.best_score, now).run();
      cert = await env.DB.prepare(
        `SELECT code, score, issued_at FROM certificates WHERE user_id = ? AND course_id = ? LIMIT 1`
      ).bind(uid, course.id).first();
    }
    certificate = cert;
  }

  return ok({
    courseId: course.id,
    slug,
    score,
    bestScore: result ? result.best_score : score,
    attempts: result ? result.attempts : 1,
    passingGrade,
    status: result ? result.status : (score >= passingGrade ? "lulus" : "belum_lulus"),
    certificate,
  });
}

// ─────────────────────────────────────────────
// 6f. ROUTE HANDLER: VERIFIKASI SERTIFIKAT (publik, tanpa login)
// ─────────────────────────────────────────────
//
//   GET /certificates/:code
//
// Publik dengan sengaja (siapa pun yang punya kode boleh memverifikasi
// keasliannya, sama seperti verifikasi sertifikat pada umumnya) — tidak
// mengekspos data lain milik peserta selain yang relevan untuk sertifikat.

async function handleCertificateLookup(env, code) {
  if (!code) return notFound("Kode sertifikat wajib diisi");

  const cert = await env.DB.prepare(`
    SELECT cert.code, cert.score, cert.issued_at,
           u.name AS name,
           c.title AS title, c.category AS category
    FROM certificates cert
    JOIN users   u ON u.id = cert.user_id
    JOIN courses c ON c.id = cert.course_id
    WHERE cert.code = ?
    LIMIT 1
  `).bind(code).first();

  if (!cert) return notFound(`Sertifikat dengan kode '${code}' tidak ditemukan / belum diterbitkan.`);

  return ok({
    code: cert.code,
    name: cert.name,
    title: cert.title,
    category: cert.category,
    score: cert.score,
    issued_at: cert.issued_at,
  });
}

// ─────────────────────────────────────────────
// 6d. ROUTE HANDLER: DASHBOARD (privat, role-aware + publik)
// ─────────────────────────────────────────────
//
//   GET /dashboard         (auth) → data berbeda per role
//   GET /dashboard/public  (tanpa auth) → agregat aman untuk halaman umum

/**
 * Rata-rata progres per kursus (dipakai dashboard admin/instruktur).
 *
 * PATCH: sebelumnya `totalModules` dihitung dari
 * `COUNT(DISTINCT p.id)` — yaitu JUMLAH BARIS PROGRES YANG PERNAH
 * DIBUAT (modul yang pernah dibuka siapa pun), BUKAN jumlah modul
 * sesungguhnya di kursus itu. Akibatnya peserta yang baru membuka
 * 1 dari 10 pertemuan langsung dianggap 100% (1 dibagi 1), karena
 * penyebutnya cuma ikut-ikutan sekecil jumlah modul yang sudah
 * disentuh, bukan jumlah modul total.
 *
 * Sekarang penyebutnya pakai `courses.module_count` (jumlah modul
 * SEBENARNYA per kursus, sama seperti `moduleCount` di katalog
 * frontend). avgProgress = total modul selesai (semua peserta) /
 * (jumlah peserta terdaftar x jumlah modul) — ini setara dengan
 * rata-rata dari (progres masing-masing peserta), karena
 * penyebutnya (module_count) sama untuk semua peserta di kursus itu.
 */
async function statsCourses(d1) {
  const { results } = await d1.prepare(`
    SELECT c.id, c.title, c.category, c.module_count,
           COUNT(DISTINCT e.id) AS enrolledCount,
           COUNT(DISTINCT CASE WHEN p.completed = 1 THEN p.id END) AS completedModules
    FROM courses c
    LEFT JOIN enrollments e ON e.course_id = c.id
    LEFT JOIN progress    p ON p.course_id = c.id
    GROUP BY c.id
    ORDER BY enrolledCount DESC
  `).all();
  return results.map(r => {
    const totalModules = r.module_count || 0;
    const denom = (r.enrolledCount || 0) * totalModules;
    return {
      ...r,
      totalModules,
      avgProgress: denom ? Math.min(100, Math.round((r.completedModules / denom) * 100)) : 0,
    };
  });
}

/**
 * Statistik kursus MILIK SEORANG INSTRUKTUR saja (courses.instructor_id
 * = instructorId) — dasar untuk "Dashboard Instruktur": berapa kursus
 * yang dia ampu, berapa peserta di tiap kursus, rata-rata progres, dan
 * berapa peserta yang sudah lulus kuis di kursus tsb.
 *
 * Pola query & perhitungan avgProgress SENGAJA disamakan dengan
 * statsCourses() di atas (Reuse · DRY) — bedanya hanya WHERE
 * c.instructor_id = ? dan tambahan kolom lulusCount.
 */
async function statsInstructorCourses(d1, instructorId) {
  const { results } = await d1.prepare(`
    SELECT c.id, c.slug, c.title, c.category, c.module_count,
           COUNT(DISTINCT e.user_id) AS enrolledCount,
           COUNT(DISTINCT CASE WHEN p.completed = 1 THEN p.id END) AS completedModules,
           COUNT(DISTINCT CASE WHEN qr.status = 'lulus' THEN qr.user_id END) AS lulusCount
    FROM courses c
    LEFT JOIN enrollments  e  ON e.course_id  = c.id
    LEFT JOIN progress     p  ON p.course_id  = c.id
    LEFT JOIN quiz_results qr ON qr.course_id = c.id
    WHERE c.instructor_id = ?
    GROUP BY c.id
    ORDER BY enrolledCount DESC
  `).bind(instructorId).all();

  return results.map(r => {
    const totalModules = r.module_count || 0;
    const denom = (r.enrolledCount || 0) * totalModules;
    return {
      ...r,
      totalModules,
      avgProgress: denom ? Math.min(100, Math.round((r.completedModules / denom) * 100)) : 0,
    };
  });
}

/** Daftar instruktur + berapa kursus yang diampu masing-masing — dipakai dashboard admin. */
async function listInstructorsWithCourseCount(d1) {
  const { results } = await d1.prepare(`
    SELECT u.id, u.name, u.email,
           COUNT(c.id) AS courseCount
    FROM users u
    LEFT JOIN courses c ON c.instructor_id = u.id
    WHERE u.role = 'instruktur'
    GROUP BY u.id
    ORDER BY u.name ASC
  `).all();
  return results;
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

  // ── ADMIN: ringkasan SELURUH platform + daftar instruktur ──
  if (hasRole(user, ["admin"])) {
    const totalPeserta = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM users WHERE role = 'peserta'`
    ).first("n");
    const totalInstruktur = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM users WHERE role = 'instruktur'`
    ).first("n");
    const totalCourses = await env.DB.prepare(`SELECT COUNT(*) AS n FROM courses`).first("n");
    const totalEnrollments = await env.DB.prepare(`SELECT COUNT(*) AS n FROM enrollments`).first("n");
    const courses = await statsCourses(env.DB);
    // PATCH: daftar instruktur + jumlah kursus yang diampu masing-masing,
    // dipakai panel admin (mis. untuk menimbang siapa yang diberi kursus
    // baru, atau siapa yang mau dikembalikan jadi peserta).
    const instructors = await listInstructorsWithCourseCount(env.DB);

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
      instructors,
    });
  }

  // ── INSTRUKTUR: HANYA kursus yang dia ampu (courses.instructor_id) ──
  // PATCH: sebelumnya instruktur melihat data yang SAMA PERSIS dengan
  // admin (ringkasan seluruh platform) — sekarang di-scope ke kursusnya
  // sendiri saja: berapa kursus, berapa peserta di tiap kursus, rata-rata
  // progres, dan berapa yang sudah lulus kuis. Ini yang dimaksud
  // "Dashboard Instruktur" (banyak kursusnya, peserta kursusnya, dll).
  if (hasRole(user, ["instruktur"])) {
    const iid = user.uid ?? user.sub;
    if (!iid) {
      return err("Sesi tidak valid (ID pengguna kosong). Silakan logout lalu login ulang dengan Google.", 401);
    }

    const myCourses = await statsInstructorCourses(env.DB, iid);
    const totalPesertaUnik = await env.DB.prepare(`
      SELECT COUNT(DISTINCT e.user_id) AS n
      FROM enrollments e
      JOIN courses c ON c.id = e.course_id
      WHERE c.instructor_id = ?
    `).bind(iid).first("n");

    return ok({
      role: user.role,
      summary: {
        totalKursus: myCourses.length,
        totalPeserta: totalPesertaUnik || 0,
        rataRataProgress: myCourses.length
          ? Math.round(myCourses.reduce((a, c) => a + c.avgProgress, 0) / myCourses.length)
          : 0,
        totalLulusKuis: myCourses.reduce((a, c) => a + (c.lulusCount || 0), 0),
      },
      myCourses,
    });
  }

  // ── PESERTA: progres belajar milik sendiri ──
  const uid = user.uid ?? user.sub;
  if (!uid) {
    return err("Sesi tidak valid (ID pengguna kosong). Silakan logout lalu login ulang dengan Google.", 401);
  }
  // PATCH: penyebutnya sekarang `c.module_count` (jumlah modul
  // SEBENARNYA di kursus), bukan `COUNT(DISTINCT p.id)` (jumlah modul
  // yang KEBETULAN sudah dibuka peserta ini). Sebelumnya baru buka
  // 1 dari 10 pertemuan langsung terhitung 100% karena penyebutnya
  // ikut cuma 1. Lihat juga statsCourses() untuk penjelasan sama.
  // PATCH: query diperkaya dengan status/nilai kuis (quiz_results) dan
  // kode sertifikat (certificates) per kursus, supaya dashboard peserta
  // bisa menampilkan "Progres Belajar & Kuis Saya" + "Sertifikat Saya"
  // tanpa request tambahan. LEFT JOIN dipakai karena belum tentu peserta
  // sudah pernah mengerjakan kuis / lulus untuk kursus tsb.
  const { results } = await env.DB.prepare(`
    SELECT c.id, c.slug, c.title, c.category, c.module_count, c.passing_grade,
           COUNT(DISTINCT CASE WHEN p.completed = 1 THEN p.module_id END) AS doneModules,
           qr.best_score  AS quizBestScore,
           qr.last_score  AS quizLastScore,
           qr.attempts    AS quizAttempts,
           qr.status      AS quizStatus,
           cert.code      AS certCode,
           cert.issued_at AS certIssuedAt
    FROM enrollments e
    JOIN courses c ON c.id = e.course_id
    LEFT JOIN progress p ON p.course_id = c.id AND p.user_id = e.user_id
    LEFT JOIN quiz_results qr ON qr.course_id = c.id AND qr.user_id = e.user_id
    LEFT JOIN certificates cert ON cert.course_id = c.id AND cert.user_id = e.user_id
    WHERE e.user_id = ?
    GROUP BY c.id
  `).bind(uid).all();

  const myCourses = results.map(r => {
    const totalModules = r.module_count || 0;
    return {
      id: r.id,
      slug: r.slug,
      title: r.title,
      category: r.category,
      totalModules,
      doneModules: r.doneModules,
      progressPct: totalModules ? Math.min(100, Math.round((r.doneModules / totalModules) * 100)) : 0,
      quiz: {
        passingGrade: r.passing_grade || 70,
        bestScore: r.quizBestScore ?? null,
        lastScore: r.quizLastScore ?? null,
        attempts: r.quizAttempts || 0,
        status: r.quizStatus || "belum_dikerjakan", // 'lulus' | 'belum_lulus' | 'belum_dikerjakan'
      },
      certificate: r.certCode ? { code: r.certCode, issuedAt: r.certIssuedAt } : null,
    };
  });

  const myCertificates = myCourses
    .filter(c => c.certificate)
    .map(c => ({ courseTitle: c.title, category: c.category, ...c.certificate }));

  return ok({
    role: user.role,
    summary: {
      totalKursusDiikuti: myCourses.length,
      rataRataProgress: myCourses.length
        ? Math.round(myCourses.reduce((a, c) => a + c.progressPct, 0) / myCourses.length)
        : 0,
      totalKuisLulus: myCourses.filter(c => c.quiz.status === "lulus").length,
      totalSertifikat: myCertificates.length,
    },
    myCourses,
    myCertificates,
  });
}

// ─────────────────────────────────────────────
// 6e. ROUTE HANDLER: UBAH ROLE PENGGUNA (admin mengangkat peserta
//     menjadi instruktur, atau mengembalikan instruktur ke peserta)
// ─────────────────────────────────────────────
//
//   PUT /users/:id/role   (auth wajib, role admin SAJA)
//   body: { role: "instruktur" | "peserta" }
//
// Sengaja dibuat sebagai handler khusus (bukan lewat CRUD generik
// PUT /users/:id) supaya:
//   1. Hanya "admin" yang boleh (CRUD generik users mengizinkan
//      admin MAUPUN instruktur, karena keduanya sama-sama lolos
//      guard SENSITIVE_TABLES — role change harus lebih ketat).
//   2. Role tujuan dibatasi whitelist ["peserta","instruktur"] —
//      role "admin" tidak bisa diberikan lewat endpoint ini, untuk
//      mencegah eskalasi hak akses (admin baru hanya dibuat manual
//      lewat wrangler.toml ADMIN_EMAILS / D1 langsung).
//   3. Akun yang SUDAH admin tidak bisa diturunkan lewat endpoint
//      ini (jaga-jaga dari salah klik / body yang keliru).

const ASSIGNABLE_ROLES = ["peserta", "instruktur"];

async function handleUserRole(request, env, id) {
  if (request.method !== "PUT") return err("Method not allowed", 405);

  const actor = await authenticate(request, env.JWT_SECRET);
  if (!actor) return noAuth();
  if (!hasRole(actor, ["admin"])) return forbidden();

  const body    = await request.json().catch(() => ({}));
  const newRole = String(body.role || "").trim();
  if (!ASSIGNABLE_ROLES.includes(newRole)) {
    return err(`role harus salah satu dari: ${ASSIGNABLE_ROLES.join(", ")}`, 400);
  }

  const target = await db.findOne(env.DB, "users", id);
  if (!target) return notFound("Pengguna tidak ditemukan");

  if (target.role === "admin") {
    return err("Role akun admin tidak bisa diubah lewat endpoint ini.", 403);
  }

  if (target.role === newRole) {
    return ok({
      id: target.id, name: target.name, email: target.email, role: target.role,
      message: `${target.name} memang sudah berperan sebagai ${newRole}.`,
    });
  }

  await db.update(env.DB, "users", id, { role: newRole });

  return ok({
    id: target.id,
    name: target.name,
    email: target.email,
    role: newRole,
    message: newRole === "instruktur"
      ? `${target.name} sekarang menjadi instruktur.`
      : `${target.name} dikembalikan menjadi peserta.`,
  });
}

// ─────────────────────────────────────────────
// 6f. ROUTE HANDLER: PENGELOLAAN BERKAS (materi video YouTube & PDF)
// ─────────────────────────────────────────────
//
//   GET    /courses/:slug/materials            (publik, tanpa login)
//          Query opsional: ?module=modul01 → hanya kembalikan berkas
//          milik modul itu + berkas umum (module_id NULL).
//   POST   /courses/:slug/materials            (auth: pemilik kursus/admin)
//          body: { type: 'video'|'pdf', title, url, description?, module_id? }
//   PUT    /materials/:id                      (auth: pemilik kursus/admin)
//   DELETE /materials/:id                      (auth: pemilik kursus/admin)
//   GET    /materials/:id                      (publik — detail satu berkas)
//
// Dibuat sebagai handler khusus (bukan CRUD generik) karena butuh:
//   1. GET publik (materi OCW boleh dibaca siapa saja, sama seperti
//      alasan `courses` tidak masuk SENSITIVE_TABLES).
//   2. Otorisasi berbasis KEPEMILIKAN kursus (courses.instructor_id),
//      bukan sekadar role — CRUD generik hanya tahu role, tidak tahu
//      "instruktur ini pemilik baris yang mana", sehingga instruktur A
//      bisa saja menambah/menghapus berkas milik kursus instruktur B
//      kalau lewat CRUD generik. Di sini itu SENGAJA dicegah.

/** true kalau `user` boleh menulis (POST/PUT/DELETE) berkas milik `course`. */
function canManageCourseMaterials(user, course) {
  if (!course) return false;
  if (hasRole(user, ["admin"])) return true;
  if (hasRole(user, ["instruktur"])) {
    const uid = user.uid ?? user.sub;
    return uid != null && String(course.instructor_id) === String(uid);
  }
  return false;
}

function serializeMaterial(row) {
  return {
    id: row.id,
    course_id: row.course_id,
    module_id: row.module_id || null,
    type: row.type,
    title: row.title,
    url: row.url,
    description: row.description || null,
    // Dihitung ulang di server tiap kali dibaca — supaya frontend tinggal
    // pakai (embed iframe) tanpa perlu regex ulang di sisi klien.
    youtubeId: row.type === "video" ? extractYouTubeId(row.url) : null,
    created_by: row.created_by,
    created_at: row.created_at,
  };
}

/** Validasi & normalisasi body POST/PUT — dipakai ulang oleh keduanya (DRY). */
function validateMaterialBody(body, { partial = false } = {}) {
  const out = {};

  if (!partial || body.type !== undefined) {
    const type = String(body.type || "").trim().toLowerCase();
    if (!MATERIAL_TYPES.includes(type)) {
      return { error: `type wajib salah satu dari: ${MATERIAL_TYPES.join(", ")}` };
    }
    out.type = type;
  }

  if (!partial || body.title !== undefined) {
    const title = String(body.title || "").trim();
    if (!title) return { error: "title wajib diisi" };
    out.title = title;
  }

  if (!partial || body.url !== undefined) {
    const url = String(body.url || "").trim();
    if (!isHttpUrl(url)) return { error: "url tidak valid (harus diawali http:// atau https://)" };

    const effectiveType = out.type || body._existingType;
    if (effectiveType === "video" && !extractYouTubeId(url)) {
      return { error: "URL video harus berupa tautan YouTube yang valid (watch?v=, youtu.be/, embed/, atau /shorts/)" };
    }
    if (effectiveType === "pdf" && !/\.pdf($|\?)/i.test(url)) {
      // Bukan hard-block (banyak link Google Drive/PDF hosting tidak
      // berakhiran .pdf) — hanya validasi kalau URL memang berbentuk file lain.
      // Tetap terima, tapi pastikan bukan tautan YouTube yang salah tempel.
      if (extractYouTubeId(url)) {
        return { error: "URL ini terdeteksi sebagai tautan YouTube — pilih jenis 'Video' untuk berkas ini" };
      }
    }
    out.url = url;
  }

  if (body.description !== undefined) {
    out.description = body.description ? String(body.description).trim() : null;
  }

  if (body.module_id !== undefined) {
    const moduleId = body.module_id ? String(body.module_id).trim() : null;
    out.module_id = moduleId || null;
  }

  return { value: out };
}

async function handleMaterials(request, env, slug) {
  const course = await env.DB.prepare(
    `SELECT id, slug, title, instructor_id FROM courses WHERE slug = ? LIMIT 1`
  ).bind(slug).first();
  if (!course) return notFound(`Kursus dengan slug '${slug}' tidak ditemukan.`);

  if (request.method === "GET") {
    const url = new URL(request.url);
    const moduleFilter = url.searchParams.get("module");

    let sql = `SELECT * FROM materials WHERE course_id = ?`;
    const binds = [course.id];
    if (moduleFilter) {
      sql += ` AND (module_id = ? OR module_id IS NULL OR module_id = '')`;
      binds.push(moduleFilter);
    }
    sql += ` ORDER BY created_at ASC`;

    const { results } = await env.DB.prepare(sql).bind(...binds).all();
    return ok(results.map(serializeMaterial));
  }

  if (request.method === "POST") {
    const user = await authenticate(request, env.JWT_SECRET);
    if (!user) return noAuth();
    if (!canManageCourseMaterials(user, course)) return forbidden();

    const uid = user.uid ?? user.sub;
    const body = await request.json().catch(() => ({}));
    const { value, error } = validateMaterialBody(body);
    if (error) return err(error, 400);

    const now = new Date().toISOString();
    const insertId = await db.insert(env.DB, "materials", {
      course_id: course.id,
      module_id: value.module_id ?? null,
      type: value.type,
      title: value.title,
      url: value.url,
      description: value.description ?? null,
      created_by: uid ?? null,
      created_at: now,
    });

    const row = await db.findOne(env.DB, "materials", insertId);
    return ok(serializeMaterial(row), { status: 201 });
  }

  return err("Method not allowed", 405);
}

async function handleMaterialItem(request, env, id) {
  const row = await db.findOne(env.DB, "materials", id);
  if (!row) return notFound("Berkas tidak ditemukan");

  if (request.method === "GET") {
    return ok(serializeMaterial(row));
  }

  // PUT & DELETE butuh login + kepemilikan kursus
  const user = await authenticate(request, env.JWT_SECRET);
  if (!user) return noAuth();

  const course = await env.DB.prepare(
    `SELECT id, slug, instructor_id FROM courses WHERE id = ? LIMIT 1`
  ).bind(row.course_id).first();
  if (!canManageCourseMaterials(user, course)) return forbidden();

  if (request.method === "PUT") {
    const body = await request.json().catch(() => ({}));
    body._existingType = row.type; // dipakai validateMaterialBody untuk validasi URL saat type tidak diubah
    const { value, error } = validateMaterialBody(body, { partial: true });
    if (error) return err(error, 400);
    if (!Object.keys(value).length) return err("Tidak ada field yang diubah");

    await db.update(env.DB, "materials", id, value);
    const updated = await db.findOne(env.DB, "materials", id);
    return ok(serializeMaterial(updated));
  }

  if (request.method === "DELETE") {
    const deleted = await db.remove(env.DB, "materials", id);
    return deleted ? ok({ deleted: true }) : notFound();
  }

  return err("Method not allowed", 405);
}

// ─────────────────────────────────────────────
// 7. ROUTE HANDLER: CRUD GENERIK
// ─────────────────────────────────────────────

// Tabel yang mengandung data lintas-pengguna (PII/relasi personal) --
// GET mentah lewat CRUD generik hanya boleh admin/instruktur. Peserta
// tetap bisa lihat datanya sendiri lewat /me dan /dashboard yang sudah
// difilter server-side, jadi tidak kehilangan fungsi apa pun.
const SENSITIVE_TABLES = ["users", "enrollments", "progress", "quiz_results", "certificates"];

// PATCH: `courses` TIDAK ada di SENSITIVE_TABLES (GET publik untuk katalog),
// tapi PENULISANNYA (POST/PUT/DELETE) tetap harus dibatasi admin/instruktur.
// Sebelum patch ini, peserta yang login bisa PUT /courses/:id dan mengubah
// `instructor_id` miliknya sendiri — celah serius sekarang bahwa
// `instructor_id` dipakai sebagai dasar Dashboard Instruktur. `id` di sini
// sengaja dipisah dari SENSITIVE_TABLES karena GET tetap boleh publik.
const WRITE_RESTRICTED_TABLES = ["courses"];

async function handleCrud(request, env, table, id) {
  if (!allowedTable(table, env))
    return notFound(`Table '${table}' not found`);

  const user = await authenticate(request, env.JWT_SECRET);
  if (!user) return noAuth();

  if (SENSITIVE_TABLES.includes(table) && !hasRole(user, ["admin", "instruktur"])) {
    return forbidden();
  }

  const method = request.method;

  if (
    WRITE_RESTRICTED_TABLES.includes(table) &&
    method !== "GET" &&
    !hasRole(user, ["admin", "instruktur"])
  ) {
    return forbidden();
  }

  // LIST
  if (method === "GET" && !id) {
    const url    = new URL(request.url);
    const page   = url.searchParams.get("page")    || 1;
    const limit  = url.searchParams.get("limit")   || 20;
    const order  = url.searchParams.get("orderBy") || "id";
    const dir    = (url.searchParams.get("dir") || "ASC").toUpperCase() === "DESC" ? "DESC" : "ASC";
    // PATCH: filter `?role=peserta` / `?role=instruktur` khusus tabel `users`
    // — dipakai panel admin untuk menampilkan daftar peserta yang bisa
    // diangkat jadi instruktur, tanpa perlu endpoint baru terpisah
    // (Reuse · DRY, whitelist ketat supaya tidak bisa dipakai filter
    // kolom sembarangan pada tabel lain).
    const where = {};
    if (table === "users") {
      const roleFilter = url.searchParams.get("role");
      if (roleFilter && ["admin", "instruktur", "peserta"].includes(roleFilter)) {
        where.role = roleFilter;
      }
    }
    const result = await db.findAll(env.DB, table, { where, orderBy: order, dir, page, limit });
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
  // /users/:id/role          → { type: "userRole", id: ":id" }     ← BARU (admin angkat instruktur)
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
  // /courses/:slug/quiz      → { type: "quiz", slug: ":slug" }         ← BARU
  // Sama alasannya dengan /enroll & /progress: harus dicek sebelum
  // fallback CRUD generik.
  if (parts[0] === "courses" && parts[1] && parts[2] === "quiz") {
    return { type: "quiz", slug: parts[1] };
  }
  // /certificates/:code      → { type: "certLookup", code: ":code" }   ← BARU
  // Publik (tanpa login) — dicek sebelum fallback CRUD generik supaya
  // tidak kena guard SENSITIVE_TABLES / whitelist tabel.
  if (parts[0] === "certificates" && parts[1]) {
    return { type: "certLookup", code: parts[1] };
  }
  // /users/:id/role          → { type: "userRole", id: ":id" }         ← BARU
  // PENTING: cek SEBELUM fallback CRUD generik, dengan alasan sama
  // seperti /courses/:slug/enroll — kalau tidak, path ini akan salah
  // kena route { table: "users", id: ":id" } (segmen "role" diabaikan)
  // dan berakhir sebagai PUT /users/:id biasa lewat handleCrud, yang
  // guard-nya lebih longgar (admin ATAU instruktur, bukan admin saja).
  if (parts[0] === "users" && parts[1] && parts[2] === "role") {
    return { type: "userRole", id: parts[1] };
  }
  // /courses/:slug/materials → { type: "materials", slug: ":slug" }    ← BARU
  // Fitur "Pengelolaan Berkas" (video YouTube & PDF oleh instruktur).
  // Sama alasannya dengan /enroll, /progress & /quiz: harus dicek
  // sebelum fallback CRUD generik.
  if (parts[0] === "courses" && parts[1] && parts[2] === "materials") {
    return { type: "materials", slug: parts[1] };
  }
  // /materials/:id          → { type: "materialItem", id: ":id" }     ← BARU
  // Endpoint terpisah (bukan CRUD generik) karena otorisasinya berbasis
  // kepemilikan kursus (courses.instructor_id), bukan sekadar role —
  // lihat canManageCourseMaterials() & komentar di handleMaterialItem().
  if (parts[0] === "materials" && parts[1]) {
    return { type: "materialItem", id: parts[1] };
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
      else if (route.type === "quiz")
        response = await handleQuizSubmit(request, env, route.slug);
      else if (route.type === "certLookup")
        response = await handleCertificateLookup(env, route.code);
      else if (route.type === "userRole")
        response = await handleUserRole(request, env, route.id);
      else if (route.type === "materials")
        response = await handleMaterials(request, env, route.slug);
      else if (route.type === "materialItem")
        response = await handleMaterialItem(request, env, route.id);
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
