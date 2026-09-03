# Setup: Login Google + Dashboard (Privat & Publik)

Fitur baru ini menyentuh **dua repo** sekaligus (microservice):

- `cf-api` → backend Cloudflare Worker (verifikasi Google, role, agregasi dashboard)
- `ocw-rpl` → frontend DonatJS (tombol Google, halaman dashboard, chart)

---

## 1. Google Cloud Console

1. Buka [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials).
2. **Create Credentials → OAuth Client ID → Web application**.
3. **Authorized JavaScript origins**: tambahkan domain frontend kamu, mis. `https://donat.id` dan `http://localhost:5500` (untuk dev).
4. Simpan **Client ID** — dipakai di dua tempat:
   - `cf-api/wrangler.toml` → `GOOGLE_CLIENT_ID`
   - `ocw-rpl/config.js` → `APP_CONFIG.GOOGLE_CLIENT_ID`

---

## 2. Backend (`cf-api`)

1. Jalankan migrasi skema D1:
   ```bash
   wrangler d1 execute cf-api --file=./schema.sql
   ```
   > Kolom `ALTER TABLE users ADD COLUMN ...` hanya boleh dijalankan **sekali**. Jika muncul
   > `duplicate column name`, berarti kolom itu sudah ada — abaikan baris tsb saja.

2. Isi `wrangler.toml`:
   ```toml
   GOOGLE_CLIENT_ID  = "xxxx.apps.googleusercontent.com"
   ADMIN_EMAILS      = "email-admin-kamu@gmail.com"
   INSTRUCTOR_EMAILS = "email-instruktur1@gmail.com,email-instruktur2@gmail.com"
   ALLOWED_TABLES    = "users,products,orders,courses,enrollments,progress"
   ```
   Email yang **tidak** ada di kedua daftar itu otomatis mendapat role `peserta` saat pertama kali login.

3. Deploy: `wrangler deploy`.

### Endpoint baru
| Method | Path              | Auth   | Keterangan |
|---|---|---|---|
| POST | `/auth/google`     | –      | Body `{ credential }` (ID token dari Google) → `{ token, user }` |
| GET  | `/me`              | Bearer | Profil user dari token aktif |
| GET  | `/dashboard`       | Bearer | Data berbeda per role (admin/instruktur = ringkasan platform, peserta = progres pribadi) |
| GET  | `/dashboard/public`| –      | Statistik agregat aman untuk halaman publik |

Tabel `courses`, `enrollments`, `progress` sudah otomatis bisa diakses lewat CRUD generik yang ada (`GET/POST/PUT/DELETE /courses`, dst.) — cukup kirim `Authorization: Bearer <token>` milik admin/instruktur.

---

## 3. Frontend (`ocw-rpl`)

1. Isi `config.js`:
   ```js
   const APP_CONFIG = {
       API_BASE_URL: 'https://cf-api.<subdomain>.workers.dev',
       GOOGLE_CLIENT_ID: 'xxxx.apps.googleusercontent.com'
   };
   ```
2. File baru yang ditambahkan (dimuat setelah `script.js`):
   - `auth-patch.js` — tombol "Sign in with Google", sesi (localStorage), pembungkus fetch ber-token.
   - `dashboard-patch.js` — rute `?dashboard` (privat, role-aware) & `?stats` (publik), komponen `statGrid`, `barChart` (SVG), `progressList`, `loginGate`.
3. `index.html` sudah diperbarui: memuat script Google Identity Services, slot `#authSlot` di header, dan tautan menu **Statistik** / **Dashboard**.

### Alur
- Klik **Sign in with Google** di header → token diverifikasi cf-api → user di-upsert ke tabel `users` (role otomatis) → sesi disimpan → diarahkan ke `?dashboard`.
- **`?dashboard`** (privat, wajib login):
  - **Peserta**: kartu ringkasan (jumlah kursus diikuti, rata-rata progres) + daftar progres per kursus.
  - **Instruktur/Admin**: kartu ringkasan platform + bar chart "Kursus Terbaik" (berdasarkan jumlah peserta) + daftar rata-rata progres semua kursus.
- **`?stats`** (publik, tanpa login): total peserta, total kursus, chart kursus terpopuler — aman ditampilkan ke siapa saja.

### Isi data contoh (opsional)
Agar dashboard langsung terisi, tambahkan kursus & progres lewat CRUD generik (token admin):
```bash
curl -X POST https://cf-api.../courses \
  -H "Authorization: Bearer <token-admin>" -H "Content-Type: application/json" \
  -d '{"title":"Rekayasa Perangkat Lunak (IMP307)","category":"RPL"}'
```
