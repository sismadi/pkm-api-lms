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
 * Upsert user hasil login Google ke tabel `users` — memakai kembali
 * db.findAll / db.insert / db.update generik (DRY, tanpa query khusus).
 */
async function upsertGoogleUser(d1, profile, env) {
  const existing = await db.findAll(d1, "users", {
    where: { google_id: profile.googleId }, limit: 1,
  });

  if (existing.rows[0]) {
    const row = existing.rows[0];
    await db.update(d1, "users", row.id, {
      name: profile.name, picture: profile.picture, last_login: new Date().toISOString(),
    });
    return { ...row, name: profile.name, picture: profile.picture };
  }

  // Cocokkan dengan akun lama berbasis email (mis. dibuat manual admin)
  const byEmail = await db.findAll(d1, "users", { where: { email: profile.email }, limit: 1 });
  if (byEmail.rows[0]) {
    const row = byEmail.rows[0];
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
  const { results } = await env.DB.prepare(`
    SELECT c.id, c.title, c.category,
           COUNT(DISTINCT p.id) AS totalModules,
           COUNT(DISTINCT CASE WHEN p.completed = 1 THEN p.id END) AS doneModules
    FROM enrollments e
    JOIN courses c ON c.id = e.course_id
    LEFT JOIN progress p ON p.course_id = c.id AND p.user_id = e.user_id
    WHERE e.user_id = ?
    GROUP BY c.id
  `).bind(user.uid).all();

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

async function handleCrud(request, env, table, id) {
  if (!allowedTable(table, env))
    return notFound(`Table '${table}' not found`);

  const user = await authenticate(request, env.JWT_SECRET);
  if (!user) return noAuth();

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
  // /auth/login          → { type: "auth" }
  // /auth/google         → { type: "auth-google" }
  // /me                  → { type: "me" }
  // /dashboard           → { type: "dashboard", scope: "private" }
  // /dashboard/public    → { type: "dashboard", scope: "public" }
  // /products            → { type: "crud", table: "products", id: null }
  // /products/42         → { type: "crud", table: "products", id: "42" }
  const parts = pathname.replace(/^\//, "").split("/");
  if (parts[0] === "auth" && parts[1] === "google") return { type: "auth-google" };
  if (parts[0] === "auth") return { type: "auth" };
  if (parts[0] === "me") return { type: "me" };
  if (parts[0] === "dashboard") return { type: "dashboard", scope: parts[1] === "public" ? "public" : "private" };
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
