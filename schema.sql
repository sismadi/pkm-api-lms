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

-- ============================================================
-- 9) PATCH: Kuis per kursus + Sertifikat otomatis — WAJIB dijalankan
--    Jalankan: wrangler d1 execute pkm-db-lms --file=./schema.sql --remote
--
--    Alur singkat:
--      1. Peserta mengerjakan kuis di frontend (quiz-patch.js), skor
--         dihitung di klien lalu dikirim ke POST /courses/:slug/quiz.
--      2. Backend menyimpan skor TERBAIK peserta per kursus di tabel
--         `quiz_results` (idempotent — boleh dikerjakan berkali-kali,
--         status/nilai selalu mencerminkan percobaan terbaik).
--      3. Begitu skor terbaik >= passing_grade kursus tsb, backend
--         OTOMATIS menerbitkan baris baru di tabel `certificates`
--         (kalau belum pernah ada) dengan kode unik, supaya sertifikat
--         hanya terbit SEKALI per (peserta, kursus).
--      4. Dashboard peserta (/dashboard) & verifikasi publik
--         (/certificates/:code) membaca dua tabel ini.
-- ============================================================

-- Ambang kelulusan per kursus (dipakai backend untuk menentukan
-- status 'lulus'/'belum_lulus'). Default 70, boleh dibedakan per kursus.
ALTER TABLE courses ADD COLUMN passing_grade REAL NOT NULL DEFAULT 70;
UPDATE courses SET passing_grade = 75 WHERE slug IN ('rpl', 'pbo', 'robotika');

CREATE TABLE IF NOT EXISTS quiz_results (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL,
  course_id     INTEGER NOT NULL,
  best_score    REAL NOT NULL DEFAULT 0,
  last_score    REAL,
  attempts      INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'belum_lulus', -- 'lulus' | 'belum_lulus'
  updated_at    TEXT,
  UNIQUE(user_id, course_id),
  FOREIGN KEY (user_id)   REFERENCES users(id),
  FOREIGN KEY (course_id) REFERENCES courses(id)
);

CREATE TABLE IF NOT EXISTS certificates (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  code         TEXT NOT NULL,
  user_id      INTEGER NOT NULL,
  course_id    INTEGER NOT NULL,
  score        REAL,
  issued_at    TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, course_id),
  FOREIGN KEY (user_id)   REFERENCES users(id),
  FOREIGN KEY (course_id) REFERENCES courses(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_code       ON certificates(code);
CREATE INDEX IF NOT EXISTS idx_quiz_user_course       ON quiz_results(user_id, course_id);
CREATE INDEX IF NOT EXISTS idx_cert_user              ON certificates(user_id);

-- ============================================================
-- 10) PATCH: Admin angkat peserta jadi instruktur + Dashboard Instruktur
--     Jalankan: wrangler d1 execute pkm-db-lms --file=./schema.sql --remote
--
--     Kolom `courses.instructor_id` SUDAH ADA sejak schema awal (lihat
--     bagian atas file ini) — patch ini HANYA menambah index supaya
--     query "kursus milik instruktur X" (dipakai handlePrivateDashboard
--     untuk role instruktur, lihat statsInstructorCourses() di index.js)
--     tidak full-scan tabel courses. Aman dijalankan berkali-kali.
--
--     Alur fitur:
--       1. Admin login → panel admin memanggil GET /users?role=peserta
--          untuk menampilkan daftar peserta yang bisa diangkat.
--       2. Admin klik "Jadikan Instruktur" → PUT /users/:id/role
--          { role: "instruktur" } (endpoint khusus, admin-only, lihat
--          handleUserRole() di index.js — TIDAK memakai CRUD generik
--          supaya lebih ketat daripada PUT /users/:id biasa).
--       3. Admin menugaskan kursus ke instruktur lewat
--          PUT /courses/:id { instructor_id: <id user instruktur> }.
--       4. Instruktur login → GET /dashboard mengembalikan HANYA
--          kursus miliknya (courses.instructor_id = uid), lengkap
--          dengan jumlah peserta & rata-rata progres per kursus.
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_courses_instructor ON courses(instructor_id);

-- ============================================================
-- 11) PATCH: Pengelolaan Berkas (Video YouTube & PDF) oleh Instruktur
--     Jalankan: wrangler d1 execute pkm-db-lms --file=./migrate-materials.sql --remote
--     (file terpisah `migrate-materials.sql` — SAMA ISINYA dengan blok di bawah,
--     dipisah supaya bisa dijalankan sendiri tanpa mengulang seluruh schema.sql)
--
--     Alur fitur:
--       1. Instruktur login → buka halaman "Kelola Berkas" (frontend:
--          materials-patch.js) → pilih salah satu kursus yang diampunya.
--       2. Instruktur mengisi form: jenis berkas (Video YouTube / PDF),
--          judul, URL, deskripsi opsional, dan modul terkait (opsional —
--          kosongkan untuk "materi umum" seluruh kursus).
--       3. Frontend memanggil POST /courses/:slug/materials (auth wajib).
--          Backend (handleMaterials di index.js) memvalidasi bahwa
--          instruktur tsb memang pemilik kursus (courses.instructor_id),
--          memvalidasi format URL (YouTube harus punya video ID valid),
--          lalu menyimpan baris baru ke tabel `materials`.
--       4. Peserta yang membuka halaman materi (learn/pbo/robotika)
--          otomatis melihat berkas ini lewat GET /courses/:slug/materials
--          (endpoint publik, tanpa login — sama seperti materi OCW
--          lainnya yang boleh dibaca publik).
--       5. Instruktur bisa menghapus berkas lewat DELETE /materials/:id
--          (hanya pemilik kursus atau admin).
-- ============================================================

CREATE TABLE IF NOT EXISTS materials (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id    INTEGER NOT NULL,
  module_id    TEXT,                    -- opsional: id modul spesifik (mis. 'modul01').
                                         -- NULL/kosong = berlaku untuk seluruh kursus.
  type         TEXT NOT NULL,           -- 'video' (YouTube) | 'pdf'
  title        TEXT NOT NULL,
  url          TEXT NOT NULL,
  description  TEXT,
  created_by   INTEGER,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (course_id)  REFERENCES courses(id),
  FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_materials_course        ON materials(course_id);
CREATE INDEX IF NOT EXISTS idx_materials_course_module ON materials(course_id, module_id);
