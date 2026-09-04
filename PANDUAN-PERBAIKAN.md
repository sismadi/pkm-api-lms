# Perbaikan: Tombol "Daftar" Tidak Terintegrasi ke Dashboard & Database

## Akar masalah

1. **Router backend tidak kenal `/courses/:slug/enroll`.**
   `parseRoute()` di `index.js` cuma mengenali `/auth`, `/me`, `/dashboard`.
   Selain itu jatuh ke handler CRUD generik: `/courses/rpl/enroll` dibaca
   sebagai tabel=`courses`, id=`rpl` (`enroll` di path diabaikan begitu
   saja). `POST` ke CRUD generik = "insert baris baru", butuh body — body
   dari frontend kosong → `400 Bad Request: "Body tidak boleh kosong"`.
   Ini persis error yang muncul di Console kamu.

2. **`courses.id` di database itu integer auto-increment**, sedangkan
   katalog di frontend pakai slug string (`rpl`, `pbo`, `robotika`). Tidak
   ada baris kursus yang cocok sama sekali di D1.

3. **`catalog-patch.js` menyembunyikan kegagalan itu.** Status "✅
   Terdaftar" disimpan ke `localStorage` DULU, baru mencoba kirim ke
   backend — dan hasil gagalnya dibungkam (`.catch(function(){})`). Jadi
   tombolnya berubah biarpun database tidak pernah benar-benar tercatat.

## Yang diperbaiki di paket ini

**`api/index.js`**
- Tambah cabang route `/courses/:slug/enroll` (dicek SEBELUM fallback ke
  CRUD generik) → `handleEnroll()` baru: cari kursus lewat `slug`,
  `INSERT OR IGNORE` ke `enrollments` (aman diklik dua kali, tidak dobel).
- Query dashboard peserta sekarang ikut mengirim `slug` supaya frontend
  bisa mencocokkan kursus dari server dengan katalog lokal.
- Tabel sensitif (`users`, `enrollments`, `progress`) sekarang hanya bisa
  di-`GET` mentah lewat endpoint CRUD generik oleh admin/instruktur —
  sebelumnya peserta biasa yang login pun bisa menarik data semua orang
  lewat `GET /users` atau `GET /enrollments`. Peserta tetap punya akses
  penuh ke datanya sendiri lewat `/me` dan `/dashboard`.

**`api/schema.sql`**
- Tambah kolom `courses.slug` + unique index.
- Seed 3 kursus (`rpl`, `pbo`, `robotika`) dengan slug yang PERSIS sama
  dengan `id` di `CATALOG_COURSES` (`catalog-patch.js`), supaya
  `POST /courses/:slug/enroll` selalu ketemu barisnya.

**`app/catalog-patch.js`**
- `completeEnroll()` sekarang MENUNGGU respons backend sebelum menandai
  "Terdaftar". Kalau backend gagal (401/500/dst), tombol kembali ke
  "Daftar" dan user diberi tahu alasannya secara jujur — bukan diam-diam
  dianggap sukses.
- Ditambah `syncEnrollmentsFromServer()`: begitu halaman dibuka & user
  sudah login, status "Terdaftar" ditarik ulang dari `/dashboard` (data
  asli di database), bukan cuma dari cache localStorage — supaya kalau
  dibuka dari HP/browser lain statusnya tetap benar.

## Cara menerapkan

### 1. Backend (`pkm-api-lms`)

```bash
# Jalankan migrasi (aman dijalankan berkali-kali; kalau ada baris yang
# sudah pernah dieksekusi sebelumnya, D1 akan bilang "duplicate column"
# untuk baris ALTER TABLE tsb -- lewati saja, lanjut baris berikutnya)
wrangler d1 execute pkm-db-lms --file=./schema.sql --remote

# Ganti isi index.js dengan versi di paket ini, lalu deploy
wrangler deploy
```

Cek hasil migrasi:
```bash
wrangler d1 execute pkm-db-lms --command="SELECT id, slug, title FROM courses;" --remote
```
Harus muncul 3 baris: `rpl`, `pbo`, `robotika`.

### 2. Frontend (`pkm-app-lms`)

Ganti isi `catalog-patch.js` dengan versi di paket ini. Tidak ada
perubahan di file lain (`auth-patch.js`, `dashboard-patch.js`, `script.js`
tetap sama). Deploy ulang seperti biasa (GitHub Pages / Cloudflare Pages /
hosting statis kamu).

### 3. Uji coba

1. Buka situs, login pakai Google.
2. Klik "Daftar" di salah satu kursus → sekarang tombol sempat menampilkan
   "Mendaftarkan..." lalu berubah "✅ Terdaftar" HANYA setelah backend
   benar-benar mengonfirmasi.
3. Buka DevTools → Network → cek request `POST .../courses/rpl/enroll`
   sekarang harus **200 OK**, bukan 400.
4. Buka menu Dashboard → kursus yang baru didaftarkan harus muncul di
   "Kursus Saya" (datanya dari `/dashboard`, benar-benar dari D1).
5. Cek langsung ke database:
   ```bash
   wrangler d1 execute pkm-db-lms --command="SELECT * FROM enrollments;" --remote
   ```
   Harus ada baris baru dengan `user_id` akun kamu.

## Catatan tambahan (opsional, tidak wajib untuk perbaikan ini)

- `dashboard-patch.js` punya `mergeLocalEnrollments()` yang menggabungkan
  cache lokal ke tampilan dashboard sebagai fallback kalau fetch server
  gagal. Ini AMAN dibiarkan — sekarang statusnya cuma dipakai sebagai
  jaring pengaman, bukan sumber kebenaran utama lagi.
- Kalau nanti mau menambah kursus baru: tambahkan objek baru di
  `CATALOG_COURSES` (frontend) DENGAN slug yang sama persis dituliskan
  juga sebagai baris baru `INSERT INTO courses (slug, title, category)`
  di database. Dua sisi ini harus selalu sinkron secara manual karena
  katalog memang didesain statis di frontend (bukan diambil dari API).
