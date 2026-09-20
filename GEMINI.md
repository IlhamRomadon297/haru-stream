# HaruStream Agent Guidelines

## Deployment & Credentials
- **MANDATORY**: Selalu periksa dan baca file `.env.deploy` sebelum melakukan deployment apa pun (`wrangler deploy`, `wrangler pages deploy`, atau query D1).
- Pastikan environment variables `CLOUDFLARE_API_TOKEN` dan `CLOUDFLARE_ACCOUNT_ID` selalu diset menggunakan nilai dari `.env.deploy`.
- Jangan pernah menimpa `account_id` dengan akun lain di luar yang tertera pada `.env.deploy`.
- **Target Akun**: Secara default, selalu lakukan deployment HANYA ke akun Cloudflare utama milik user yang tertera di `.env.deploy`. Jangan deploy ke akun teman kecuali user secara eksplisit meminta untuk dideploy ke akun temannya.

## Shell & Command Execution
- Di Antigravity IDE (Windows PowerShell environment), **JANGAN PERNAH** menggunakan operator `&&` untuk merangkai perintah. Operator `&&` tidak valid dan akan menyebabkan syntax/parser error.
- **Wajib menggunakan titik koma (`;`)** sebagai pemisah perintah beruntun (contoh: `git add . ; git commit -m "..." ; git push origin main`).
- **HTTP / URL Testing**: Selalu gunakan Node.js (`node -e "fetch('...').then(...)"`) untuk pengujian URL, status HTTP, atau endpoint API. **JANGAN gunakan `curl`** karena di PowerShell `curl` adalah alias `Invoke-WebRequest` yang sering hang atau menimbulkan error parsing argumen.

## D1 Read Efficiency & Testing Guardrails (Learned)
- **D1 Read Budget Awareness**: Kuota gratis D1 harian adalah 5.000.000 rows read. Saat bereksperimen, memperbaiki bug, atau menambah fitur baru, **DILARANG KERAS** membiarkan query melakukan pemindaian berulang yang boros atau memicu sync berulang tanpa kontrol yang menguras kuota D1.
- **Simulasi & Pengujian Aman**: Utamakan validasi struktur query dan indeks (misal via SQLite lokal/in-memory) sebelum melakukan testing berulang ke live D1 production agar kuota harian tidak meledak saat eksperimen.
- **Fitur Andalan User**: Interval Auto-sync 30 menit dan Manual Sync adalah fitur andalan user, **JANGAN diubah intervalnya**. Fokus optimasi murni pada algoritma diffing (hanya sinkronisasi video yang baru masuk, folder masuk, pindah folder, atau video terhapus) agar pemrosesan seminimal mungkin.
- **Akurasi Batas Cloudflare Free Tier**:
  - D1 Free: 5.000.000 rows read/hari, 100.000 rows written/hari.
  - Workers KV Free: 100.000 reads/hari, 1.000 writes/hari (jangan tertukar dengan paket Workers Paid/Enterprise).

## Permanent Video ID Immobility (Learned)
- **ID Video Wajib Permanen (Immutable)**: **DILARANG KERAS** mengubah, menimpa, atau meregenerasi `id` setiap video yang ada di D1 (`videos.id`), KECUALI jika videonya memang dihapus (baik via tombol hapus user maupun karena file sudah hilang di cloud storage).
- **Integritas Link & Embed**: ID video adalah identitas mutlak yang dipakai oleh embed player, streaming URL, API bot, dan link publik. Semua proses sync/update hanya boleh memperbarui metadata (title, size, thumbnail, folder_id, dll) tanpa pernah mengubah `id` baris video yang bersangkutan.

