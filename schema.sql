-- ============================================================
-- schema.sql — Migrasi D1 untuk fitur Login Google + Dashboard
-- Jalankan: wrangler d1 execute cf-api --file=./schema.sql
-- ============================================================

-- 1) Tabel `users` sudah ada (id, name, email) — tambahkan kolom baru.
--    SQLite/D1 tidak mendukung "ADD COLUMN IF NOT EXISTS", jadi jalankan
--    baris di bawah SATU KALI saja. Jika error "duplicate column", berarti
--    kolom itu sudah pernah ditambahkan — lewati baris tsb dan lanjut.
ALTER TABLE users ADD COLUMN google_id  TEXT;
ALTER TABLE users ADD COLUMN picture    TEXT;
ALTER TABLE users ADD COLUMN role       TEXT NOT NULL DEFAULT 'peserta';
ALTER TABLE users ADD COLUMN created_at TEXT;
ALTER TABLE users ADD COLUMN last_login TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);

-- 2) Tabel kursus
CREATE TABLE IF NOT EXISTS courses (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  title         TEXT NOT NULL,
  description   TEXT,
  category      TEXT,
  instructor_id INTEGER,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (instructor_id) REFERENCES users(id)
);

-- 3) Pendaftaran peserta ke kursus
CREATE TABLE IF NOT EXISTS enrollments (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL,
  course_id   INTEGER NOT NULL,
  enrolled_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, course_id),
  FOREIGN KEY (user_id)   REFERENCES users(id),
  FOREIGN KEY (course_id) REFERENCES courses(id)
);

-- 4) Progres per-modul peserta (dipakai untuk chart & dashboard)
CREATE TABLE IF NOT EXISTS progress (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL,
  course_id    INTEGER NOT NULL,
  module_id    TEXT NOT NULL,
  completed    INTEGER NOT NULL DEFAULT 0,
  score        REAL,
  completed_at TEXT,
  UNIQUE(user_id, course_id, module_id),
  FOREIGN KEY (user_id)   REFERENCES users(id),
  FOREIGN KEY (course_id) REFERENCES courses(id)
);

CREATE INDEX IF NOT EXISTS idx_enroll_course      ON enrollments(course_id);
CREATE INDEX IF NOT EXISTS idx_enroll_user         ON enrollments(user_id);
CREATE INDEX IF NOT EXISTS idx_progress_user_course ON progress(user_id, course_id);

-- 5) (Opsional) contoh data kursus supaya dashboard langsung terisi
-- INSERT INTO courses (title, category) VALUES
--   ('Rekayasa Perangkat Lunak (IMP307)', 'RPL'),
--   ('Pemrograman Web dengan DonatJS', 'Web');

-- ============================================================
-- 6) PATCH: fitur "Daftar Kursus" (enroll) — WAJIB dijalankan
--    Jalankan: wrangler d1 execute pkm-db-lms --file=./schema.sql --remote
--    Sama seperti bagian (1): SQLite/D1 tidak mendukung
--    "ADD COLUMN IF NOT EXISTS". Kalau muncul error "duplicate column",
--    berarti kolom itu sudah pernah ditambahkan -- lewati baris itu saja,
--    lanjut ke baris berikutnya.
-- ============================================================

ALTER TABLE courses ADD COLUMN slug TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_courses_slug ON courses(slug);

-- Slug HARUS sama persis dengan `id` di CATALOG_COURSES (catalog-patch.js),
-- karena tombol "Daftar" memanggil POST /courses/:slug/enroll memakai
-- nilai `id` itu apa adanya.
INSERT OR IGNORE INTO courses (slug, title, category) VALUES
  ('rpl',      'Rekayasa Perangkat Lunak',      'RPL'),
  ('pbo',      'Pemrograman Berorientasi Objek', 'PBO'),
  ('robotika', 'Robotika Dasar',                 'Robotika');

-- ============================================================
-- 7) PATCH: jumlah modul SEBENARNYA per kursus — WAJIB dijalankan
--    Jalankan: wrangler d1 execute pkm-db-lms --file=./schema.sql --remote
--
--    Dipakai sebagai PENYEBUT saat menghitung persentase progres
--    (lihat statsCourses() & handlePrivateDashboard() di index.js).
--    Sebelum kolom ini ada, penyebutnya salah dihitung dari jumlah
--    modul yang KEBETULAN sudah dibuka peserta -> baru buka 1 modul
--    langsung tampil 100%.
--
--    HARUS SAMA PERSIS dengan `moduleCount` di CATALOG_COURSES
--    (catalog-patch.js). Kalau nanti jumlah modul sebuah kursus
--    berubah, update DUA tempat ini sekaligus (frontend & DB).
-- ============================================================

ALTER TABLE courses ADD COLUMN module_count INTEGER NOT NULL DEFAULT 0;

UPDATE courses SET module_count = 16 WHERE slug = 'rpl';
UPDATE courses SET module_count = 12 WHERE slug = 'pbo';
UPDATE courses SET module_count = 10 WHERE slug = 'robotika';
