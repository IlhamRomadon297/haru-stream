/**
 * HaruStream PRO - Cloudflare Worker Core
 * =========================================
 * Serverless video streaming aggregator and management system.
 * Runs on Cloudflare Workers + D1 Database.
 *
 * Architecture:
 *  - JWT-based authentication (HS256 via WebCrypto)
 *  - Multi-user Google Drive credential management (D1)
 *  - Virtual folder system (100% decoupled from GDrive)
 *  - Stream-bridge for remote URL → GDrive upload
 *  - ArtPlayer embed endpoint with view counter
 */

// ============================================================
// CONSTANTS & HELPERS
// ============================================================

const CORS_HEADERS = (origin = '*') => ({
  'Access-Control-Allow-Origin': origin,
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
});

const JSON_HEADERS = { 'Content-Type': 'application/json' };
const HTML_HEADERS = { 'Content-Type': 'text/html;charset=UTF-8' };

// JWT Secret key cached per isolate lifetime
let cachedJwtKey = null;

/**
 * Derive a CryptoKey from the JWT_SECRET env var (HMAC-SHA256).
 */
async function getJwtKey(secret) {
  if (cachedJwtKey) return cachedJwtKey;
  const encoder = new TextEncoder();
  cachedJwtKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  return cachedJwtKey;
}

/**
 * Base64url encode a Uint8Array.
 */
function base64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64url decode a string to Uint8Array.
 */
function fromBase64url(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

/**
 * Sign a JWT payload (HS256).
 */
async function signJwt(payload, secret, expiresInSeconds = 604800) {
  const key = await getJwtKey(secret);
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now, exp: now + expiresInSeconds };
  const encoder = new TextEncoder();
  const headerB64 = base64url(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64url(encoder.encode(JSON.stringify(fullPayload)));
  const sigInput = `${headerB64}.${payloadB64}`;
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(sigInput));
  return `${sigInput}.${base64url(sig)}`;
}

/**
 * Verify a JWT and return its payload, or null if invalid/expired.
 */
async function verifyJwt(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const key = await getJwtKey(secret);
    const encoder = new TextEncoder();
    const sigInput = `${parts[0]}.${parts[1]}`;
    const sig = fromBase64url(parts[2]);
    const valid = await crypto.subtle.verify('HMAC', key, sig, encoder.encode(sigInput));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(fromBase64url(parts[1])));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

/**
 * Hash a password with PBKDF2 (WebCrypto safe for Cloudflare Workers).
 */
async function hashPassword(password, salt = null) {
  const encoder = new TextEncoder();
  const saltBytes = salt
    ? fromBase64url(salt)
    : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hashB64 = base64url(derivedBits);
  const saltB64 = base64url(saltBytes);
  return { hash: `${saltB64}:${hashB64}`, saltB64 };
}

/**
 * Verify a password against a stored hash (salt:hash format).
 */
async function verifyPassword(password, storedHash) {
  try {
    const [saltB64] = storedHash.split(':');
    const { hash } = await hashPassword(password, saltB64);
    return hash === storedHash;
  } catch {
    return false;
  }
}

/**
 * Extract Bearer token from Authorization header.
 */
function extractToken(request) {
  const auth = request.headers.get('Authorization') || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

/**
 * Authenticate a request and return the user payload, or null.
 */
async function authenticate(request, env) {
  const token = extractToken(request);
  if (!token) return null;
  return await verifyJwt(token, env.JWT_SECRET || 'harustream-default-secret-change-me');
}

/**
 * Build a JSON response.
 */
function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

/**
 * Build an error JSON response.
 */
function errorResponse(message, status = 400, extraHeaders = {}) {
  return jsonResponse({ success: false, error: message }, status, extraHeaders);
}

// ============================================================
// GOOGLE DRIVE API HELPERS
// ============================================================

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_DRIVE_API  = 'https://www.googleapis.com/drive/v3';
const GOOGLE_UPLOAD_API = 'https://www.googleapis.com/upload/drive/v3';

/**
 * Fetch a fresh Google access token using the stored refresh token.
 * Updates the access_token and token_expires_at in D1.
 */
async function getAccessToken(drive, db) {
  const now = Date.now();
  // Return cached token if still valid (with 60s buffer)
  if (drive.access_token && drive.token_expires_at) {
    const expiresAt = new Date(drive.token_expires_at).getTime();
    if (now < expiresAt - 60000) {
      return drive.access_token;
    }
  }

  // Refresh the token
  const resp = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     drive.client_id,
      client_secret: drive.client_secret,
      refresh_token: drive.refresh_token,
      grant_type:    'refresh_token',
    }),
  });

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Google token refresh failed: ${err}`);
  }

  const data = await resp.json();
  const expiresAt = new Date(now + data.expires_in * 1000).toISOString();

  await db.prepare(
    `UPDATE drives SET access_token = ?, token_expires_at = ?, updated_at = datetime('now') WHERE id = ?`
  ).bind(data.access_token, expiresAt, drive.id).run();

  drive.access_token = data.access_token;
  return data.access_token;
}

/**
 * List video files from a Google Drive account.
 * Paginates automatically through all results.
 */
async function listDriveVideos(drive, db, pageToken = null) {
  const accessToken = await getAccessToken(drive, db);
  const mimeFilter = "mimeType contains 'video/'";
  const folderFilter = drive.root_folder_id
    ? ` and '${drive.root_folder_id}' in parents`
    : '';
  const query = encodeURIComponent(`${mimeFilter}${folderFilter} and trashed = false`);
  const fields = 'nextPageToken,files(id,name,size,mimeType,modifiedTime,videoMediaMetadata,thumbnailLink)';
  let url = `${GOOGLE_DRIVE_API}/files?q=${query}&fields=${encodeURIComponent(fields)}&pageSize=1000&supportsAllDrives=true`;
  if (pageToken) url += `&pageToken=${encodeURIComponent(pageToken)}`;

  const resp = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!resp.ok) throw new Error(`GDrive list failed: ${await resp.text()}`);
  return await resp.json();
}

/**
 * Get a direct download/stream link for a GDrive file.
 */
async function getDriveStreamUrl(driveFileId, accessToken) {
  return `${GOOGLE_DRIVE_API}/files/${driveFileId}?alt=media`;
}

/**
 * Get GDrive quota info for a drive account.
 */
async function getDriveQuota(drive, db) {
  const accessToken = await getAccessToken(drive, db);
  const resp = await fetch(`${GOOGLE_DRIVE_API}/about?fields=storageQuota`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!resp.ok) return { used: 0, total: 0 };
  const data = await resp.json();
  return {
    used:  parseInt(data.storageQuota?.usage || 0),
    total: parseInt(data.storageQuota?.limit  || 0),
  };
}

/**
 * Parse a human-readable resolution string from GDrive video metadata.
 */
function parseResolution(videoMediaMetadata) {
  if (!videoMediaMetadata) return null;
  const { width, height } = videoMediaMetadata;
  if (!width || !height) return null;
  const h = parseInt(height);
  if (h >= 2160) return '4K';
  if (h >= 1440) return '1440p';
  if (h >= 1080) return '1080p';
  if (h >= 720)  return '720p';
  if (h >= 480)  return '480p';
  return `${width}x${height}`;
}

// ============================================================
// ROUTE HANDLERS
// ============================================================

// ── AUTH ────────────────────────────────────────────────────

// Public registration is DISABLED — access restricted to seeded admin only.
async function handleRegister(request, env) {
  return errorResponse('Registration is disabled. This system uses a single admin account.', 403);
}

/**
 * Seed the master admin account if it does not already exist.
 * Called once during Worker startup (via initializeApp).
 */
async function seedAdminAccount(env) {
  try {
    const existing = await env.DB.prepare(
      `SELECT id FROM users WHERE username = 'harumisato' LIMIT 1`
    ).first();
    if (existing) return; // Already seeded, skip

    const { hash } = await hashPassword('HarumiChan2970');
    await env.DB.prepare(
      `INSERT OR IGNORE INTO users (username, password_hash, role) VALUES ('harumisato', ?, 'admin')`
    ).bind(hash).run();
  } catch {
    // Silently ignore — may already exist or DB not ready yet
  }
}

async function handleLogin(request, env) {
  const { username, password } = await request.json().catch(() => ({}));
  if (!username || !password) return errorResponse('Username and password are required.');

  try {
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?')
      .bind(username.toLowerCase()).first();
    if (!user) return errorResponse('Invalid credentials.', 401);

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) return errorResponse('Invalid credentials.', 401);

    const jwtSecret = env.JWT_SECRET || 'harustream-default-secret-change-me';
    const token = await signJwt(
      { sub: user.id, username: user.username, role: user.role },
      jwtSecret
    );

    return jsonResponse({
      success: true,
      token,
      user: { id: user.id, username: user.username, role: user.role, avatar_url: user.avatar_url },
    });
  } catch (e) {
    return errorResponse(`Login failed: ${e.message}`, 500);
  }
}

// ── DRIVES ──────────────────────────────────────────────────

async function handleListDrives(request, env, user) {
  const drives = await env.DB.prepare(
    `SELECT id, drive_name, root_folder_id, quota_used, quota_total, last_synced_at, is_active, created_at
     FROM drives WHERE user_id = ? ORDER BY created_at DESC`
  ).bind(user.sub).all();
  return jsonResponse({ success: true, drives: drives.results });
}

async function handleAddDrive(request, env, user) {
  const { drive_name, client_id, client_secret, refresh_token, root_folder_id } =
    await request.json().catch(() => ({}));
  if (!drive_name || !client_id || !client_secret || !refresh_token) {
    return errorResponse('drive_name, client_id, client_secret, and refresh_token are required.');
  }

  try {
    // Validate the refresh token by attempting to fetch a new access token
    const testResp = await fetch(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id, client_secret, refresh_token, grant_type: 'refresh_token',
      }),
    });
    if (!testResp.ok) {
      const errBody = await testResp.text();
      return errorResponse(`Invalid Google Drive credentials: ${errBody}`, 422);
    }
    const tokenData = await testResp.json();
    const accessToken  = tokenData.access_token;
    const expiresAt    = new Date(Date.now() + tokenData.expires_in * 1000).toISOString();

    const result = await env.DB.prepare(
      `INSERT INTO drives
        (user_id, drive_name, client_id, client_secret, refresh_token, access_token, token_expires_at, root_folder_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(user.sub, drive_name, client_id, client_secret, refresh_token, accessToken, expiresAt, root_folder_id || null).run();

    return jsonResponse({ success: true, drive_id: result.meta?.last_row_id }, 201);
  } catch (e) {
    return errorResponse(`Failed to add drive: ${e.message}`, 500);
  }
}

async function handleDeleteDrive(driveId, env, user) {
  const drive = await env.DB.prepare('SELECT id FROM drives WHERE id = ? AND user_id = ?')
    .bind(driveId, user.sub).first();
  if (!drive) return errorResponse('Drive not found.', 404);

  await env.DB.prepare('DELETE FROM drives WHERE id = ?').bind(driveId).run();
  return jsonResponse({ success: true, message: 'Drive removed.' });
}

// ── SYNC ────────────────────────────────────────────────────

async function handleSync(request, env, user) {
  const { drive_id } = await request.json().catch(() => ({}));

  let drivesQuery;
  if (drive_id) {
    drivesQuery = await env.DB.prepare('SELECT * FROM drives WHERE id = ? AND user_id = ? AND is_active = 1')
      .bind(drive_id, user.sub).all();
  } else {
    drivesQuery = await env.DB.prepare('SELECT * FROM drives WHERE user_id = ? AND is_active = 1')
      .bind(user.sub).all();
  }

  const drives = drivesQuery.results;
  if (!drives.length) return errorResponse('No active drives found.', 404);

  let totalSynced = 0;
  let totalSkipped = 0;
  const errors = [];

  for (const drive of drives) {
    try {
      let pageToken = null;
      do {
        const data = await listDriveVideos(drive, env.DB, pageToken);
        const files = data.files || [];

        // ── Incremental sync: only write if new or actually changed ──────────
        // Fetch all existing drive_file_ids from this drive in one query
        const existingMap = new Map();
        if (files.length > 0) {
          const ids = files.map(f => f.id);
          // SQLite supports up to 999 params; chunk if needed
          const chunkSize = 200;
          for (let ci = 0; ci < ids.length; ci += chunkSize) {
            const chunk = ids.slice(ci, ci + chunkSize);
            const placeholders = chunk.map(() => '?').join(',');
            const rows = await env.DB.prepare(
              `SELECT drive_file_id, title, size, drive_modified_at FROM videos
               WHERE drive_file_id IN (${placeholders})`
            ).bind(...chunk).all();
            for (const r of rows.results) {
              existingMap.set(r.drive_file_id, r);
            }
          }
        }

        const insertStmts = [];
        const updateStmts = [];

        for (const file of files) {
          const resolution = parseResolution(file.videoMediaMetadata);
          const duration   = file.videoMediaMetadata?.durationMillis
            ? Math.round(parseInt(file.videoMediaMetadata.durationMillis) / 1000)
            : 0;
          const fileSize   = parseInt(file.size || 0);
          const existing   = existingMap.get(file.id);

          if (!existing) {
            // Brand new file — INSERT
            insertStmts.push(
              env.DB.prepare(
                `INSERT OR IGNORE INTO videos
                  (user_id, drive_id, drive_file_id, title, size, mime_type, resolution, duration, thumbnail_url, drive_modified_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
              ).bind(
                user.sub, drive.id, file.id, file.name, fileSize,
                file.mimeType, resolution, duration,
                file.thumbnailLink || null, file.modifiedTime || null
              )
            );
          } else {
            // Existing file — only UPDATE if something actually changed
            const modifiedChanged = existing.drive_modified_at !== (file.modifiedTime || null);
            const sizeChanged     = existing.size !== fileSize;
            const titleChanged    = existing.title !== file.name;
            if (modifiedChanged || sizeChanged || titleChanged) {
              updateStmts.push(
                env.DB.prepare(
                  `UPDATE videos SET
                     title = ?, size = ?, resolution = ?, duration = ?,
                     thumbnail_url = ?, drive_modified_at = ?,
                     updated_at = datetime('now')
                   WHERE drive_file_id = ?`
                ).bind(
                  file.name, fileSize, resolution, duration,
                  file.thumbnailLink || null, file.modifiedTime || null,
                  file.id
                )
              );
            } else {
              totalSkipped++;
              continue;
            }
          }
        }

        const allStmts = [...insertStmts, ...updateStmts];
        if (allStmts.length > 0) {
          await env.DB.batch(allStmts);
          totalSynced += allStmts.length;
        }

        pageToken = data.nextPageToken || null;
      } while (pageToken);

      // Update quota and last_synced_at
      const quota = await getDriveQuota(drive, env.DB);
      await env.DB.prepare(
        `UPDATE drives SET quota_used = ?, quota_total = ?, last_synced_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`
      ).bind(quota.used, quota.total, drive.id).run();

    } catch (e) {
      errors.push({ drive_id: drive.id, drive_name: drive.drive_name, error: e.message });
    }
  }

  return jsonResponse({
    success: true,
    synced: totalSynced,
    skipped: totalSkipped,
    errors,
    message: `Sync complete. ${totalSynced} files indexed.`,
  });
}

// ── MEDIA ───────────────────────────────────────────────────

async function handleListMedia(request, env, user) {
  const url    = new URL(request.url);
  const search = url.searchParams.get('search') || '';
  const folderId = url.searchParams.get('folder_id') || null;
  const sortBy   = url.searchParams.get('sort_by') || 'title';
  const sortDir  = (url.searchParams.get('sort_dir') || 'asc').toUpperCase() === 'DESC' ? 'DESC' : 'ASC';
  const page     = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
  const limit    = Math.min(200, parseInt(url.searchParams.get('limit') || '50'));
  const offset   = (page - 1) * limit;

  const validSorts = { title: 'v.title', size: 'v.size', views: 'v.views', downloads: 'v.downloads', created_at: 'v.created_at', modified: 'v.drive_modified_at', resolution: 'v.resolution' };
  const orderCol = validSorts[sortBy] || 'v.title';

  let whereClause = 'WHERE v.user_id = ?';
  const bindings = [user.sub];

  if (folderId) {
    whereClause += ' AND v.folder_id = ?';
    bindings.push(parseInt(folderId));
  } else if (url.searchParams.get('folder_id') === 'null') {
    whereClause += ' AND v.folder_id IS NULL';
  }

  if (search) {
    whereClause += ' AND (v.title LIKE ? OR v.tags LIKE ?)';
    bindings.push(`%${search}%`, `%${search}%`);
  }

  const countResult = await env.DB.prepare(
    `SELECT COUNT(*) as total FROM videos v ${whereClause}`
  ).bind(...bindings).first();

  const videos = await env.DB.prepare(
    `SELECT v.id, v.drive_file_id, v.title, v.size, v.resolution, v.duration,
            v.views, v.downloads, v.mime_type, v.thumbnail_url, v.folder_id,
            v.is_public, v.tags, v.drive_modified_at, v.created_at, v.updated_at,
            d.drive_name, f.name as folder_name
     FROM videos v
     LEFT JOIN drives  d ON d.id = v.drive_id
     LEFT JOIN folders f ON f.id = v.folder_id
     ${whereClause}
     ORDER BY ${orderCol} ${sortDir}
     LIMIT ? OFFSET ?`
  ).bind(...bindings, limit, offset).all();

  // Fetch virtual folders for folder tree navigation
  const folders = await env.DB.prepare(
    `SELECT id, parent_id, name, color, icon, sort_order FROM folders WHERE user_id = ? ORDER BY sort_order, name`
  ).bind(user.sub).all();

  return jsonResponse({
    success: true,
    total: countResult?.total || 0,
    page,
    limit,
    videos: videos.results,
    folders: folders.results,
  });
}

async function handleCreateFolder(request, env, user) {
  const { name, parent_id, color, icon } = await request.json().catch(() => ({}));
  if (!name) return errorResponse('Folder name is required.');

  if (parent_id) {
    const parent = await env.DB.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?')
      .bind(parent_id, user.sub).first();
    if (!parent) return errorResponse('Parent folder not found.', 404);
  }

  const result = await env.DB.prepare(
    `INSERT INTO folders (user_id, parent_id, name, color, icon) VALUES (?, ?, ?, ?, ?)`
  ).bind(user.sub, parent_id || null, name, color || '#6366f1', icon || 'folder').run();

  return jsonResponse({ success: true, folder_id: result.meta?.last_row_id }, 201);
}

async function handleMoveVideo(request, env, user) {
  const { video_ids, folder_id } = await request.json().catch(() => ({}));
  if (!video_ids || !Array.isArray(video_ids)) return errorResponse('video_ids array is required.');

  const stmts = video_ids.map(vid =>
    env.DB.prepare(
      `UPDATE videos SET folder_id = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?`
    ).bind(folder_id || null, vid, user.sub)
  );

  await env.DB.batch(stmts);
  return jsonResponse({ success: true, moved: video_ids.length });
}

async function handleDeleteVideos(request, env, user) {
  const { video_ids } = await request.json().catch(() => ({}));
  if (!video_ids || !Array.isArray(video_ids)) return errorResponse('video_ids array is required.');

  const stmts = video_ids.map(vid =>
    env.DB.prepare('DELETE FROM videos WHERE id = ? AND user_id = ?').bind(vid, user.sub)
  );
  await env.DB.batch(stmts);
  return jsonResponse({ success: true, deleted: video_ids.length });
}

// ── REMOTE UPLOAD ────────────────────────────────────────────

async function handleRemoteUpload(request, env, user) {
  const { urls, drive_id, folder_id, title_prefix } = await request.json().catch(() => ({}));
  if (!urls || !Array.isArray(urls) || urls.length === 0) {
    return errorResponse('urls array is required.');
  }
  if (!drive_id) return errorResponse('drive_id is required.');

  const drive = await env.DB.prepare('SELECT * FROM drives WHERE id = ? AND user_id = ?')
    .bind(drive_id, user.sub).first();
  if (!drive) return errorResponse('Drive not found.', 404);

  const results = [];

  for (let i = 0; i < urls.length; i++) {
    const remoteUrl = urls[i].trim();
    if (!remoteUrl) continue;

    try {
      const accessToken = await getAccessToken(drive, env.DB);
      // Fetch remote URL
      const remoteResp = await fetch(remoteUrl);
      if (!remoteResp.ok) throw new Error(`Failed to fetch remote URL: ${remoteUrl}`);

      const contentType = remoteResp.headers.get('content-type') || 'video/mp4';
      const contentLength = remoteResp.headers.get('content-length');
      const filename = title_prefix
        ? `${title_prefix}_${String(i + 1).padStart(3, '0')}.mp4`
        : remoteUrl.split('/').pop().split('?')[0] || `video_${Date.now()}.mp4`;

      // Initiate resumable upload to Google Drive
      const initResp = await fetch(`${GOOGLE_UPLOAD_API}/files?uploadType=resumable&supportsAllDrives=true`, {
        method: 'POST',
        headers: {
          Authorization:   `Bearer ${accessToken}`,
          'Content-Type':  'application/json',
          'X-Upload-Content-Type': contentType,
          ...(contentLength ? { 'X-Upload-Content-Length': contentLength } : {}),
        },
        body: JSON.stringify({
          name: filename,
          mimeType: contentType,
          ...(drive.root_folder_id ? { parents: [drive.root_folder_id] } : {}),
        }),
      });

      if (!initResp.ok) throw new Error(`GDrive resumable init failed: ${await initResp.text()}`);
      const uploadUrl = initResp.headers.get('Location');

      // Stream the body directly to Google Drive
      const uploadResp = await fetch(uploadUrl, {
        method: 'PUT',
        headers: {
          'Content-Type': contentType,
          ...(contentLength ? { 'Content-Length': contentLength } : {}),
        },
        body: remoteResp.body,
        duplex: 'half',
      });

      if (!uploadResp.ok) throw new Error(`GDrive upload failed: ${await uploadResp.text()}`);
      const fileData = await uploadResp.json();

      // Index into D1
      await env.DB.prepare(
        `INSERT INTO videos (user_id, drive_id, folder_id, drive_file_id, title, mime_type)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(drive_file_id) DO NOTHING`
      ).bind(user.sub, drive.id, folder_id || null, fileData.id, filename, contentType).run();

      results.push({ url: remoteUrl, status: 'success', drive_file_id: fileData.id, filename });
    } catch (e) {
      results.push({ url: remoteUrl, status: 'error', error: e.message });
    }
  }

  return jsonResponse({ success: true, results });
}

// ── EMBED / STREAM ───────────────────────────────────────────

async function handleEmbed(driveFileId, request, env) {
  // Increment view count (fire-and-forget)
  env.DB.prepare(
    `UPDATE videos SET views = views + 1, updated_at = datetime('now') WHERE drive_file_id = ?`
  ).bind(driveFileId).run().catch(() => {});

  // Find the drive credentials for this file
  const video = await env.DB.prepare(
    `SELECT v.*, d.client_id, d.client_secret, d.refresh_token, d.access_token, d.token_expires_at, d.id as drive_row_id
     FROM videos v JOIN drives d ON d.id = v.drive_id WHERE v.drive_file_id = ?`
  ).bind(driveFileId).first();

  if (!video) {
    return new Response('Video not found.', { status: 404, headers: HTML_HEADERS });
  }

  // Build the proxy stream URL (served by this same Worker)
  const baseUrl   = new URL(request.url);
  const streamUrl = `${baseUrl.origin}/stream/${driveFileId}`;

  const html = buildEmbedPage(video, streamUrl, driveFileId);
  return new Response(html, { headers: HTML_HEADERS });
}

async function handleStream(driveFileId, request, env) {
  const video = await env.DB.prepare(
    `SELECT v.*, d.client_id, d.client_secret, d.refresh_token, d.access_token, d.token_expires_at, d.id as drive_row_id
     FROM videos v JOIN drives d ON d.id = v.drive_id WHERE v.drive_file_id = ?`
  ).bind(driveFileId).first();

  if (!video) return new Response('Video not found.', { status: 404 });

  const fakeDrive = {
    id: video.drive_row_id,
    client_id:       video.client_id,
    client_secret:   video.client_secret,
    refresh_token:   video.refresh_token,
    access_token:    video.access_token,
    token_expires_at: video.token_expires_at,
    root_folder_id:  null,
  };

  let accessToken;
  try {
    accessToken = await getAccessToken(fakeDrive, env.DB);
  } catch (e) {
    return new Response(`Auth error: ${e.message}`, { status: 502 });
  }

  const driveStreamUrl = `${GOOGLE_DRIVE_API}/files/${driveFileId}?alt=media&supportsAllDrives=true`;

  // Proxy the request with the range header forwarded
  const rangeHeader = request.headers.get('Range');
  const driveResp = await fetch(driveStreamUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      ...(rangeHeader ? { Range: rangeHeader } : {}),
    },
  });

  const responseHeaders = new Headers();
  const copyHeaders = ['Content-Type', 'Content-Length', 'Content-Range', 'Accept-Ranges'];
  for (const h of copyHeaders) {
    const v = driveResp.headers.get(h);
    if (v) responseHeaders.set(h, v);
  }
  responseHeaders.set('Cache-Control', 'public, max-age=3600');
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');

  const url = new URL(request.url);
  if (url.searchParams.get('download') === '1') {
    const filename = video.title.replace(/"/g, '\\"');
    responseHeaders.set('Content-Disposition', `attachment; filename="${filename}"`);
  }

  return new Response(driveResp.body, {
    status: driveResp.status,
    headers: responseHeaders,
  });
}

// ── STATS ────────────────────────────────────────────────────

async function handleStats(env, user) {
  const stats = await env.DB.prepare(`
    SELECT
      COALESCE(SUM(views), 0)     as total_views,
      COALESCE(SUM(downloads), 0) as total_downloads,
      COALESCE(SUM(size), 0)      as total_size,
      COUNT(*)                    as total_videos
    FROM videos WHERE user_id = ?
  `).bind(user.sub).first();

  const topVideos = await env.DB.prepare(
    `SELECT drive_file_id, title, views, downloads, size, resolution
     FROM videos WHERE user_id = ? ORDER BY views DESC LIMIT 10`
  ).bind(user.sub).all();

  const recentActivity = await env.DB.prepare(
    `SELECT title, views, created_at FROM videos WHERE user_id = ? ORDER BY created_at DESC LIMIT 7`
  ).bind(user.sub).all();

  const driveCount = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM drives WHERE user_id = ? AND is_active = 1'
  ).bind(user.sub).first();

  return jsonResponse({
    success: true,
    stats: {
      total_views:     stats?.total_views     || 0,
      total_downloads: stats?.total_downloads || 0,
      total_size:      stats?.total_size      || 0,
      total_videos:    stats?.total_videos    || 0,
      total_drives:    driveCount?.cnt        || 0,
    },
    top_videos:      topVideos.results,
    recent_activity: recentActivity.results,
  });
}

// ── EMBED HTML TEMPLATE ──────────────────────────────────────

function buildEmbedPage(video, streamUrl, driveFileId) {
  // Detect if this is a heavy format (MKV / HEVC / AV1 / multi-track)
  const mime      = (video.mime_type || '').toLowerCase();
  const titleLow  = (video.title    || '').toLowerCase();
  const isHeavy   = mime.includes('x-matroska') || mime.includes('mkv') ||
                    titleLow.endsWith('.mkv') || titleLow.endsWith('.hevc') ||
                    titleLow.endsWith('.av1');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(video.title)} — HaruStream PRO</title>
  <meta name="robots" content="noindex">
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html,body{width:100%;height:100%;background:#000;overflow:hidden}
    #artplayer-container{width:100%;height:100vh}
    .art-video-player{background:#000}

    /* ── Warning Modal ─────────────────────────────────── */
    #warn-modal {
      position:fixed;inset:0;z-index:9999;
      background:rgba(0,0,0,0.88);
      backdrop-filter:blur(12px);
      display:flex;align-items:center;justify-content:center;
    }
    .warn-box {
      background:linear-gradient(135deg,#141428,#1a1a36);
      border:1px solid rgba(99,102,241,0.35);
      border-radius:20px;padding:36px 32px;
      max-width:480px;width:94%;text-align:center;
      box-shadow:0 32px 80px rgba(0,0,0,0.9),0 0 0 1px rgba(99,102,241,0.1);
      animation:warnIn .35s cubic-bezier(.34,1.56,.64,1);
    }
    @keyframes warnIn{from{opacity:0;transform:scale(.88) translateY(24px)}to{opacity:1;transform:scale(1) translateY(0)}}
    .warn-icon{
      width:64px;height:64px;border-radius:50%;
      background:linear-gradient(135deg,rgba(239,68,68,.2),rgba(245,158,11,.15));
      border:2px solid rgba(239,68,68,.4);
      display:flex;align-items:center;justify-content:center;
      margin:0 auto 20px;
    }
    .warn-title{font-size:18px;font-weight:700;color:#fff;margin-bottom:10px;font-family:Inter,sans-serif}
    .warn-body{font-size:13.5px;line-height:1.65;color:#94a3b8;font-family:Inter,sans-serif;margin-bottom:28px}
    .warn-ext-group{display:flex;flex-direction:column;gap:8px;margin-bottom:18px}
    .warn-ext-btn{
      display:flex;align-items:center;gap:10px;
      padding:11px 16px;border-radius:12px;border:1px solid rgba(99,102,241,0.35);
      background:rgba(99,102,241,0.12);color:#a5b4fc;
      font-size:13px;font-weight:600;cursor:pointer;
      text-align:left;transition:all .18s;
      font-family:Inter,sans-serif;
    }
    .warn-ext-btn:hover{background:rgba(99,102,241,0.28);border-color:rgba(99,102,241,0.6);color:#c7d2fe;transform:translateY(-1px)}
    .warn-ext-btn svg{flex-shrink:0;opacity:.8}
    .warn-force-btn{
      width:100%;padding:11px 16px;border-radius:12px;
      background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
      color:#64748b;font-size:12.5px;font-weight:600;cursor:pointer;
      transition:all .18s;font-family:Inter,sans-serif;
    }
    .warn-force-btn:hover{background:rgba(255,255,255,0.08);color:#94a3b8}

    /* ── External player dropdown ──────────────────────── */
    #ext-menu-wrap{position:relative;display:inline-block}
    #ext-dropdown{
      position:absolute;bottom:calc(100% + 8px);right:0;
      background:#1a1a36;border:1px solid rgba(99,102,241,0.3);
      border-radius:12px;padding:6px;
      display:none;flex-direction:column;gap:2px;
      min-width:220px;z-index:500;
      box-shadow:0 16px 48px rgba(0,0,0,0.9);
      animation:fadeUp .15s ease-out;
    }
    #ext-dropdown.open{display:flex}
    @keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
    .ext-item{
      display:flex;align-items:center;gap:8px;
      padding:8px 12px;border-radius:8px;
      color:#a5b4fc;font-size:12px;font-weight:600;
      cursor:pointer;transition:all .15s;
      font-family:Inter,sans-serif;
    }
    .ext-item:hover{background:rgba(99,102,241,0.18);color:#c7d2fe}
  </style>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>

  <!-- ── Heavy Format Warning Modal ──────────────── -->
  ${isHeavy ? `
  <div id="warn-modal">
    <div class="warn-box">
      <div class="warn-icon">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      </div>
      <div class="warn-title">⚠ Peringatan: Format Berat Terdeteksi</div>
      <div class="warn-body">
        Video ini menggunakan format berkualitas tinggi <strong style="color:#fbbf24">(MKV/AV1/Multi-track)</strong> yang sangat berat untuk browser.<br><br>
        Disarankan memutarnya di <strong style="color:#a5b4fc">Aplikasi Eksternal</strong> agar 100% lancar tanpa lag, dengan dukungan audio & subtitle penuh.
      </div>
      <div class="warn-ext-group">
        <button class="warn-ext-btn" onclick="openExternal('potplayer')">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="#a5b4fc"><path d="M8 5v14l11-7z"/></svg>
          Buka di PotPlayer (Windows)
        </button>
        <button class="warn-ext-btn" onclick="openExternal('vlc')">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="#a5b4fc"><path d="M8 5v14l11-7z"/></svg>
          Buka di VLC (Cross-platform)
        </button>
        <button class="warn-ext-btn" onclick="openExternal('mx')">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="#a5b4fc"><path d="M8 5v14l11-7z"/></svg>
          Buka di MX Player (Android)
        </button>
      </div>
      <button class="warn-force-btn" onclick="dismissWarningAndPlay()">
        🧩 Tetap Paksa Putar di Browser (WASM)
      </button>
    </div>
  </div>` : ''}

  <div id="artplayer-container"></div>

  <script src="https://cdn.jsdelivr.net/npm/artplayer@5/dist/artplayer.js"></script>

  <!-- SubtitlesOctopus (libass WASM) -->
  <script src="https://cdn.jsdelivr.net/npm/libass-wasm@4/dist/js/subtitles-octopus.js"></script>

  <script>
    const videoTitle  = ${JSON.stringify(video.title)};
    const streamUrl   = ${JSON.stringify(streamUrl)};
    const driveFileId = ${JSON.stringify(driveFileId)};
    const isHeavy     = ${isHeavy ? 'true' : 'false'};

    // ── External player deep-links ───────────────────────────
    function openExternal(player) {
      const url = streamUrl;
      if (player === 'potplayer')  window.location.href = 'potplayer://' + url;
      else if (player === 'vlc')   window.location.href = 'vlc://' + url;
      else if (player === 'mx')    window.location.href = 'intent:' + url + '#Intent;package=com.mxtech.videoplayer.ad;type=video/*;end';
    }

    // ── Toggle external player dropdown ─────────────────────
    function toggleExtMenu() {
      const d = document.getElementById('ext-dropdown');
      if (d) d.classList.toggle('open');
    }
    document.addEventListener('click', (e) => {
      const wrap = document.getElementById('ext-menu-wrap');
      if (wrap && !wrap.contains(e.target)) {
        const d = document.getElementById('ext-dropdown');
        if (d) d.classList.remove('open');
      }
    });

    // ── Initialize the player ────────────────────────────────
    let art = null;
    let wasmPlayerActive = false;

    function initPlayer() {
      art = new Artplayer({
        container: '#artplayer-container',
        url:       streamUrl,
        title:     videoTitle,
        autoplay:  !isHeavy, // Only autoplay if NOT heavy (heavy requires user gesture after modal)
        pip:       true,
        screenshot: true,
        setting:   true,
        loop:      false,
        flip:      true,
        playbackRate: true,
        aspectRatio: true,
        fullscreen:  true,
        fullscreenWeb: true,
        miniProgressBar: true,
        hotkey: true,
        lock: true,
        fastForward: true,
        autoSize: true,
        autoMini: false,
        theme: '#6366f1',
        lang: 'en',
        moreVideoAttr: {
          crossOrigin: 'anonymous',
          preload: 'metadata',
        },
        controls: [
          // ── Download button ──────────────────────────────
          {
            position: 'right',
            html: '<button title="Download" style="color:#fff;background:rgba(99,102,241,.15);border:1px solid rgba(99,102,241,.35);border-radius:8px;cursor:pointer;font-size:12px;padding:4px 10px;font-weight:600">⬇ DL</button>',
            click: () => {
              const a = document.createElement('a');
              a.href = streamUrl + '?download=1';
              a.download = videoTitle;
              a.click();
            },
          },
          // ── External Player dropdown button ──────────────
          {
            position: 'right',
            html: '<div id="ext-menu-wrap" style="position:relative">' +
                  '<button onclick="toggleExtMenu()" title="Buka di Aplikasi Eksternal" ' +
                  'style="color:#a5b4fc;background:rgba(99,102,241,.15);border:1px solid rgba(99,102,241,.35);border-radius:8px;cursor:pointer;font-size:12px;padding:4px 10px;font-weight:600">▶ Eksternal</button>' +
                  '<div id="ext-dropdown">' +
                  '<div class="ext-item" onclick="openExternal(\'potplayer\')">' +
                  '<svg width="14" height="14" viewBox="0 0 24 24" fill="#a5b4fc"><path d="M8 5v14l11-7z"/></svg>PotPlayer (Windows)</div>' +
                  '<div class="ext-item" onclick="openExternal(\'vlc\')">' +
                  '<svg width="14" height="14" viewBox="0 0 24 24" fill="#a5b4fc"><path d="M8 5v14l11-7z"/></svg>VLC (Cross-platform)</div>' +
                  '<div class="ext-item" onclick="openExternal(\'mx\')">' +
                  '<svg width="14" height="14" viewBox="0 0 24 24" fill="#a5b4fc"><path d="M8 5v14l11-7z"/></svg>MX Player (Android)</div>' +
                  '</div></div>',
          },
        ],
        plugins: [],
      });

      art.on('ready', () => {
        console.log('[HaruStream] Player ready:', videoTitle, '| Heavy:', isHeavy);
      });

      // ── F-key fullscreen ─────────────────────────────────
      document.addEventListener('keydown', (e) => {
        if (e.key === 'f' || e.key === 'F') {
          e.preventDefault();
          if (art) art.fullscreen = !art.fullscreen;
        }
      });

      // ── View tracking beacon ─────────────────────────────
      art.on('video:ended', () => {
        navigator.sendBeacon('/api/media/track', JSON.stringify({
          drive_file_id: driveFileId,
          event: 'complete'
        }));
      });
    }

    // ── Warning Modal dismiss: initialize WASM + player ─────
    function dismissWarningAndPlay() {
      const modal = document.getElementById('warn-modal');
      if (modal) modal.style.display = 'none';

      // Initialize Artplayer first
      initPlayer();

      // Attempt to load the MKV via the native <video> element
      // Modern Chromium can partially decode H.264 MKV natively
      // For full AC3/multi-track support we hint the user to use external players.
      // If you add an ffmpeg.wasm pipeline in the future, bootstrap it here.
      if (art) {
        art.play();
      }
    }

    // ── Startup logic ─────────────────────────────────────
    if (isHeavy) {
      // Heavy format: show the warning modal; player is initialized only
      // after the user makes an explicit choice (see warn buttons above).
      // Player is NOT initialized here to avoid wasted MSE/decode attempts.
    } else {
      // Lightweight MP4/AVC: initialize player immediately
      initPlayer();
    }
  </script>
</body>
</html>`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── TRACKING (fire-and-forget) ────────────────────────────────

async function handleTrack(request, env) {
  try {
    const { drive_file_id, event } = await request.json();
    if (!drive_file_id) return new Response('', { status: 204 });
    if (event === 'download') {
      await env.DB.prepare(
        `UPDATE videos SET downloads = downloads + 1 WHERE drive_file_id = ?`
      ).bind(drive_file_id).run();
    }
    return new Response('', { status: 204 });
  } catch {
    return new Response('', { status: 204 });
  }
}

// ============================================================
// MAIN ROUTER
// ============================================================

// Track whether admin seeding has been attempted in this isolate lifetime
let adminSeeded = false;

export default {
  async fetch(request, env, ctx) {
    // Seed master admin account once per isolate (non-blocking)
    if (!adminSeeded) {
      adminSeeded = true;
      ctx.waitUntil(seedAdminAccount(env));
    }
    const url    = new URL(request.url);
    const method = request.method.toUpperCase();
    const path   = url.pathname;

    // ── CORS Preflight ──────────────────────────────────────
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS(env.CORS_ORIGIN || '*'),
      });
    }

    const corsHeaders = CORS_HEADERS(env.CORS_ORIGIN || '*');

    // ── Static Embed & Stream (no auth) ─────────────────────
    if (method === 'GET' && path.startsWith('/embed/')) {
      const fileId = path.slice('/embed/'.length);
      return await handleEmbed(fileId, request, env);
    }

    if (method === 'GET' && path.startsWith('/stream/')) {
      const fileId = path.slice('/stream/'.length);
      return await handleStream(fileId, request, env);
    }

    // ── Beacon (no auth) ────────────────────────────────────
    if (method === 'POST' && path === '/api/media/track') {
      return await handleTrack(request, env);
    }

    // ── Auth endpoints (no auth required) ───────────────────
    if (method === 'POST' && path === '/api/auth/register') {
      // Registration is disabled — return 403 immediately
      return jsonResponse({ success: false, error: 'Registration is disabled.' }, 403, corsHeaders);
    }
    if (method === 'POST' && path === '/api/auth/login') {
      const res = await handleLogin(request, env);
      addCorsHeaders(res, corsHeaders);
      return res;
    }

    // ── Protected routes ────────────────────────────────────
    const user = await authenticate(request, env);
    if (!user) {
      return jsonResponse({ success: false, error: 'Unauthorized.' }, 401, corsHeaders);
    }

    let res;

    // Drives
    if (path === '/api/settings/drives') {
      if (method === 'GET')  res = await handleListDrives(request, env, user);
      else if (method === 'POST') res = await handleAddDrive(request, env, user);
      else res = errorResponse('Method not allowed.', 405);
    }
    else if (path.startsWith('/api/settings/drives/') && method === 'DELETE') {
      const driveId = parseInt(path.split('/').pop());
      res = await handleDeleteDrive(driveId, env, user);
    }

    // Sync
    else if (path === '/api/media/sync' && method === 'POST') {
      res = await handleSync(request, env, user);
    }

    // Media
    else if (path === '/api/media') {
      if (method === 'GET')  res = await handleListMedia(request, env, user);
      else if (method === 'DELETE') res = await handleDeleteVideos(request, env, user);
      else res = errorResponse('Method not allowed.', 405);
    }
    else if (path === '/api/media/move' && method === 'POST') {
      res = await handleMoveVideo(request, env, user);
    }

    // Folders
    else if (path === '/api/folders' && method === 'POST') {
      res = await handleCreateFolder(request, env, user);
    }

    // Remote upload
    else if (path === '/api/media/upload/remote' && method === 'POST') {
      res = await handleRemoteUpload(request, env, user);
    }

    // Stats
    else if (path === '/api/stats' && method === 'GET') {
      res = await handleStats(env, user);
    }

    // Me
    else if (path === '/api/auth/me' && method === 'GET') {
      res = jsonResponse({ success: true, user: { id: user.sub, username: user.username, role: user.role } });
    }

    // Fallthrough → serve public SPA (handled by Cloudflare Pages)
    else {
      res = errorResponse('Not Found.', 404);
    }

    addCorsHeaders(res, corsHeaders);
    return res;
  },
};

function addCorsHeaders(res, corsHeaders) {
  if (!res) return;
  for (const [k, v] of Object.entries(corsHeaders)) {
    res.headers.set(k, v);
  }
}
