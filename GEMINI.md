# HaruStream Agent Guidelines

## Deployment & Credentials
- **MANDATORY**: Selalu periksa dan baca file `.env.deploy` sebelum melakukan deployment apa pun (`wrangler deploy`, `wrangler pages deploy`, atau query D1).
- Pastikan environment variables `CLOUDFLARE_API_TOKEN` dan `CLOUDFLARE_ACCOUNT_ID` selalu diset menggunakan nilai dari `.env.deploy`.
- Jangan pernah menimpa `account_id` dengan akun lain di luar yang tertera pada `.env.deploy`.
