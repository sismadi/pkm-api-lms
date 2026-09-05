-- ============================================================
-- migrate-quiz-cert.sql
-- HANYA berisi patch KUIS & SERTIFIKAT (bagian 9 dari schema.sql).
-- Jalankan file INI SAJA — jangan paste ulang seluruh schema.sql,
-- karena bagian atasnya (ALTER TABLE users ADD COLUMN google_id, dst)
-- sudah pernah berhasil dijalankan sebelumnya. Menjalankannya lagi
-- akan memicu error "duplicate column name: google_id", dan karena
-- D1 Studio menjalankan satu paste sebagai satu batch, error di awal
-- itu membuat SEMUA statement setelahnya (termasuk tabel quiz_results
-- & certificates di bawah) tidak benar-benar ter-commit — walau UI
-- sempat menampilkan "Executed 26/26".
--
-- Cara jalan (pilih salah satu):
--   A. wrangler:
--      wrangler d1 execute pkm-db-lms --file=./migrate-quiz-cert.sql --remote
--   B. D1 Studio (Cloudflare Dashboard):
--      Buka tab Query -> hapus isi editor -> paste ISI FILE INI SAJA -> Run.
--
-- Aman dijalankan berkali-kali KECUALI dua baris ALTER TABLE di bawah:
-- kalau muncul error "duplicate column name: passing_grade", berarti
-- baris itu sudah pernah berhasil sebelumnya — lewati baris itu saja
-- (hapus dari editor), lalu jalankan sisanya.
-- ============================================================

ALTER TABLE courses ADD COLUMN passing_grade REAL NOT NULL DEFAULT 70;
UPDATE courses SET passing_grade = 75 WHERE slug IN ('rpl', 'pbo', 'robotika');

CREATE TABLE IF NOT EXISTS quiz_results (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL,
  course_id     INTEGER NOT NULL,
  best_score    REAL NOT NULL DEFAULT 0,
  last_score    REAL,
  attempts      INTEGER NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'belum_lulus',
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
-- Verifikasi setelah dijalankan — dua baris ini harus mengembalikan
-- baris hasil (bukan error "no such table"):
--   SELECT * FROM quiz_results LIMIT 1;
--   SELECT * FROM certificates LIMIT 1;
-- Dan di sidebar D1 Studio, tabel `quiz_results` & `certificates`
-- harus muncul di daftar tabel sebelah kiri.
-- ============================================================
