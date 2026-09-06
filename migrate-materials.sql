-- ============================================================
-- migrate-materials.sql
-- PATCH: fitur "Pengelolaan Berkas" — instruktur/dosen menambahkan
-- link video YouTube dan/atau PDF sebagai materi tambahan per kursus
-- (opsional: dikaitkan ke modul tertentu, mis. 'modul01').
--
-- Jalankan file INI SAJA (jangan paste ulang schema.sql):
--   A. wrangler:
--      wrangler d1 execute pkm-db-lms --file=./migrate-materials.sql --remote
--   B. D1 Studio (Cloudflare Dashboard):
--      Tab Query -> hapus isi editor -> paste ISI FILE INI SAJA -> Run.
--
-- Aman dijalankan berkali-kali (CREATE TABLE/INDEX IF NOT EXISTS).
-- ============================================================

CREATE TABLE IF NOT EXISTS materials (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id    INTEGER NOT NULL,
  module_id    TEXT,                    -- opsional: id modul spesifik (mis. 'modul01').
                                         -- NULL/kosong = berlaku untuk seluruh kursus ("materi umum").
  type         TEXT NOT NULL,           -- 'video' (YouTube) | 'pdf'
  title        TEXT NOT NULL,
  url          TEXT NOT NULL,
  description  TEXT,
  created_by   INTEGER,                 -- users.id milik instruktur yang mengunggah
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (course_id)  REFERENCES courses(id),
  FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_materials_course        ON materials(course_id);
CREATE INDEX IF NOT EXISTS idx_materials_course_module  ON materials(course_id, module_id);

-- ============================================================
-- Verifikasi setelah dijalankan — harus mengembalikan baris hasil
-- (bukan error "no such table"):
--   SELECT * FROM materials LIMIT 1;
-- ============================================================
