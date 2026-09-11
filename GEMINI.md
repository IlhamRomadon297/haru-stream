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
