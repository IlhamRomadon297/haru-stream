# Deployment Rules for HaruStream

## 1. Cloudflare Environment & Credentials
- **MANDATORY**: Selalu periksa dan baca file `.env.deploy` terlebih dahulu sebelum menjalankan perintah `wrangler deploy`, `wrangler pages deploy`, atau interaksi apa pun dengan Cloudflare / D1 / Pages.
- File `.env.deploy` berisi kredensial deploy yang valid:
  - `CLOUDFLARE_API_TOKEN`
  - `CLOUDFLARE_ACCOUNT_ID`
  - `HS_JWT_SECRET`
- Jalankan perintah deployment dengan memuat environment variables dari `.env.deploy`, contoh di PowerShell:
  ```powershell
  # Load env variables from .env.deploy
  Get-Content .env.deploy | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
      [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
  }
  npx wrangler deploy
  ```
  atau untuk Pages:
  ```powershell
  Get-Content .env.deploy | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
      [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
  }
  npx wrangler pages deploy public --project-name=haru-stream
  ```
- **Jangan pernah mengganti `account_id` di `wrangler.toml`** secara sembarangan tanpa mencocokkan dengan `CLOUDFLARE_ACCOUNT_ID` yang ada di `.env.deploy`.
