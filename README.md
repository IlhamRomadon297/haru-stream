# HaruStream PRO 🎬

**Advanced serverless video streaming aggregator and management system**

Built on Cloudflare Workers + D1 Database + Google Drive API

---

## ✨ Features

- 🔐 **JWT Authentication** — Secure PBKDF2 password hashing, 7-day session tokens
- ☁️ **Multi-Drive Management** — Connect unlimited Google Drive accounts with OAuth2
- 📁 **Virtual Folder System** — 100% decoupled from Google Drive's physical layout
- 🔄 **Smart Sync Engine** — Batch-index videos from all connected drives into D1
- 🎥 **ArtPlayer Embed** — Full-featured player with SubtitlesOctopus (.ass libass WASM)
- 🌐 **Stream Proxy** — Range-request-aware proxy with view counter
- 📤 **Remote URL Upload** — Pipe external URLs directly into Google Drive via streams
- 📊 **Analytics Dashboard** — Chart.js Area + Donut charts, top video stats
- 📋 **Export Engine** — Export embed codes, links, metadata respecting active sort order

---

## 🚀 Deployment

### 1. Prerequisites

```bash
npm install
npx wrangler login
```

### 2. Create D1 Database

```bash
npx wrangler d1 create haru-stream-db
# Copy the database_id from output → paste into wrangler.toml
```

### 3. Apply Schema

```bash
npm run db:init
```

### 4. Set JWT Secret

```bash
npx wrangler secret put JWT_SECRET
# Enter a long random string when prompted
```

### 5. Deploy Worker

```bash
npm run deploy
```

### 6. Deploy Pages (Frontend)

```bash
npx wrangler pages deploy ./public --project-name=haru-stream
```

---

## 📁 Project Structure

```
haru-stream/
├── schema.sql          # D1 database schema
├── wrangler.toml       # Cloudflare configuration
├── package.json
├── src/
│   └── index.js        # Cloudflare Worker (API + Embed)
└── public/
    └── index.html      # SPA Dashboard (Tailwind + Chart.js + FontAwesome)
```

---

## 🔑 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login, returns JWT |
| GET  | `/api/auth/me` | Current user info |
| GET  | `/api/settings/drives` | List connected drives |
| POST | `/api/settings/drives` | Add Google Drive credentials |
| DELETE | `/api/settings/drives/:id` | Remove a drive |
| POST | `/api/media/sync` | Sync/index videos from GDrive |
| GET  | `/api/media` | List videos with search + sort + pagination |
| POST | `/api/media/move` | Move videos to virtual folder |
| DELETE | `/api/media` | Delete indexed videos |
| POST | `/api/folders` | Create virtual folder |
| POST | `/api/media/upload/remote` | Remote URL → GDrive stream upload |
| GET  | `/api/stats` | Dashboard statistics |
| GET  | `/embed/:drive_file_id` | ArtPlayer embed page |
| GET  | `/stream/:drive_file_id` | Proxied video stream |

---

## ⚙️ Environment Variables

| Variable | Description | How to Set |
|----------|-------------|------------|
| `JWT_SECRET` | Secret key for JWT signing | `wrangler secret put JWT_SECRET` |
| `DB` | D1 database binding | `wrangler.toml` |

---

## 📜 License

MIT © HaruStream PRO
