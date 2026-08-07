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
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, Range',
  'Access-Control-Max-Age': '86400',
});

const JSON_HEADERS = { 'Content-Type': 'application/json' };
const HTML_HEADERS = { 
  'Content-Type': 'text/html;charset=UTF-8',
  'Cache-Control': 'no-cache, no-store, must-revalidate',
  'Access-Control-Allow-Origin': '*',
  'Content-Security-Policy': 'frame-ancestors *;',
};

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
 * Get all descendant folder IDs (including root_folder_id) to support recursive syncing.
 */
async function getDescendantFolders(drive, db) {
  if (!drive.root_folder_id) return null; // null means sync entire drive
  const rootId = drive.root_folder_id;
  const accessToken = await getAccessToken(drive, db);
  
  const validSet = new Set([rootId]);
  const queue = [rootId];
  const CHUNK_SIZE = 25; // max ~1800 chars for query to stay under 2048 URL limit

  while (queue.length > 0) {
    const batch = queue.splice(0, CHUNK_SIZE);
    const parentQuery = batch.map(id => `'${id}' in parents`).join(' or ');
    const query = encodeURIComponent(`mimeType = 'application/vnd.google-apps.folder' and trashed = false and (${parentQuery})`);
    
    let pageToken = null;
    do {
      let url = `${GOOGLE_DRIVE_API}/files?q=${query}&fields=nextPageToken,files(id)&pageSize=1000&supportsAllDrives=true&includeItemsFromAllDrives=true&corpora=allDrives`;
      if (pageToken) url += `&pageToken=${encodeURIComponent(pageToken)}`;
      
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
      if (!resp.ok) throw new Error(`GDrive folder fetch failed: ${await resp.text()}`);
      
      const data = await resp.json();
      if (data.files) {
        for (const f of data.files) {
          if (!validSet.has(f.id)) {
            validSet.add(f.id);
            queue.push(f.id);
          }
        }
      }
      pageToken = data.nextPageToken;
    } while (pageToken);
  }
  return validSet;
}

/**
 * Fetch all videos in the drive, or only within descendant folders if root_folder_id is set.
 */
async function fetchAllDriveVideos(drive, db, validFolderIds) {
  const accessToken = await getAccessToken(drive, db);
  const fields = 'nextPageToken,files(id,name,size,mimeType,modifiedTime,videoMediaMetadata,thumbnailLink,parents,trashed)';
  let results = [];

  // If validFolderIds is null (entire drive sync), query all active files owned by 'me' directly
  if (!validFolderIds) {
    const query = encodeURIComponent("trashed = false and 'me' in owners");
    let pageToken = null;
    do {
      let url = `${GOOGLE_DRIVE_API}/files?q=${query}&fields=${encodeURIComponent(fields)}&pageSize=1000&corpora=user`;
      if (pageToken) url += `&pageToken=${encodeURIComponent(pageToken)}`;
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
      if (!resp.ok) throw new Error(`GDrive list failed: ${await resp.text()}`);
      const data = await resp.json();
      if (data.files) {
        const videos = data.files.filter(f => {
          if (f.trashed) return false;
          if (f.mimeType && f.mimeType.startsWith('video/')) return true;
          if (!f.name) return false;
          const ext = f.name.split('.').pop().toLowerCase();
          return ['mkv','mp4','avi','webm','mov','flv','wmv','m4v','ts'].includes(ext);
        });
        results.push(...videos);
      }
      pageToken = data.nextPageToken;
    } while (pageToken);
    return results;
  }
  
  const folderArray = Array.from(validFolderIds);
  const CHUNK_SIZE = 25; // max safe size for query string
  for (let i = 0; i < folderArray.length; i += CHUNK_SIZE) {
    const chunk = folderArray.slice(i, i + CHUNK_SIZE);
    const parentQuery = chunk.map(id => `'${id}' in parents`).join(' or ');
    const query = encodeURIComponent(`trashed = false and (${parentQuery})`);
    
    let pageToken = null;
    do {
      let url = `${GOOGLE_DRIVE_API}/files?q=${query}&fields=${encodeURIComponent(fields)}&pageSize=1000&supportsAllDrives=true&includeItemsFromAllDrives=true&corpora=allDrives`;
      if (pageToken) url += `&pageToken=${encodeURIComponent(pageToken)}`;
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
      if (!resp.ok) throw new Error(`GDrive list failed: ${await resp.text()}`);
      const data = await resp.json();
      if (data.files) {
        const videos = data.files.filter(f => {
          if (f.trashed) return false;
          if (f.mimeType && f.mimeType.startsWith('video/')) return true;
          if (!f.name) return false;
          const ext = f.name.split('.').pop().toLowerCase();
          return ['mkv','mp4','avi','webm','mov','flv','wmv','m4v','ts'].includes(ext);
        });
        results.push(...videos);
      }
      pageToken = data.nextPageToken;
    } while (pageToken);
  }
  return results;
}

async function getStartPageToken(drive, db) {
  const accessToken = await getAccessToken(drive, db);
  const resp = await fetch(`${GOOGLE_DRIVE_API}/changes/startPageToken?supportsAllDrives=true`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!resp.ok) throw new Error('Failed to fetch startPageToken');
  const data = await resp.json();
  return data.startPageToken;
}

async function getDriveChanges(drive, db, pageToken) {
  const accessToken = await getAccessToken(drive, db);
  let url = `${GOOGLE_DRIVE_API}/changes?pageToken=${encodeURIComponent(pageToken)}&supportsAllDrives=true&includeItemsFromAllDrives=true&pageSize=1000&fields=nextPageToken,newStartPageToken,changes(fileId,removed,file(id,name,size,mimeType,modifiedTime,videoMediaMetadata,thumbnailLink,parents,trashed))`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) throw new Error('Failed to fetch changes');
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



async function performDriveSync(drive, env, forceFullScan = false) {
  let totalSynced  = 0;
  let totalRemoved = 0;

  const validFolderIds = await getDescendantFolders(drive, env.DB);

  // 1. Fetch active video files from GDrive for this drive
  const gdriveFiles = await fetchAllDriveVideos(drive, env.DB, validFolderIds);
  const gdriveMap = new Map();
  for (const f of gdriveFiles) {
    gdriveMap.set(f.id, f);
  }

  // 2. Fetch existing video records from D1 for this drive
  const d1Query = await env.DB.prepare(
    `SELECT drive_file_id, title, size FROM videos WHERE drive_id = ?`
  ).bind(drive.id).all();
  
  const d1Map = new Map();
  if (d1Query.results) {
    for (const row of d1Query.results) {
      d1Map.set(row.drive_file_id, row);
    }
  }

  const insertStmts = [];
  const deleteStmts = [];

  // 3. Diff: find NEW or MODIFIED files (skip unchanged files to save D1 write operations!)
  for (const [fileId, file] of gdriveMap.entries()) {
    const existing = d1Map.get(fileId);
    const size = parseInt(file.size || 0);

    // If file is already in D1 with matching title and size, SKIP IT!
    if (existing && existing.title === file.name && existing.size === size) {
      continue;
    }

    const resolution = parseResolution(file.videoMediaMetadata);
    const duration   = file.videoMediaMetadata?.durationMillis ? Math.round(parseInt(file.videoMediaMetadata.durationMillis) / 1000) : 0;

    insertStmts.push(
      env.DB.prepare(
        `INSERT INTO videos (user_id, drive_id, drive_file_id, title, size, mime_type, resolution, duration, thumbnail_url, drive_modified_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(drive_file_id) DO UPDATE SET title=excluded.title, size=excluded.size, mime_type=excluded.mime_type, resolution=excluded.resolution, duration=excluded.duration, thumbnail_url=excluded.thumbnail_url, drive_modified_at=datetime('now'), drive_id=excluded.drive_id`
      ).bind(drive.user_id, drive.id, file.id, file.name, size, file.mimeType, resolution, duration, file.thumbnailLink || null, file.modifiedTime || null)
    );
  }

  // 4. Diff: find DELETED / TRASHED files
  for (const [d1FileId] of d1Map.entries()) {
    if (!gdriveMap.has(d1FileId)) {
      deleteStmts.push(env.DB.prepare(`DELETE FROM videos WHERE drive_file_id = ? AND drive_id = ?`).bind(d1FileId, drive.id));
    }
  }

  // 5. Execute DB batch operations (only execute if there are actual inserts/deletes!)
  if (deleteStmts.length > 0) {
    for (let i = 0; i < deleteStmts.length; i += 50) {
      await env.DB.batch(deleteStmts.slice(i, i + 50));
    }
    totalRemoved = deleteStmts.length;
  }

  if (insertStmts.length > 0) {
    for (let i = 0; i < insertStmts.length; i += 50) {
      await env.DB.batch(insertStmts.slice(i, i + 50));
    }
    totalSynced = insertStmts.length;
  }

  // 6. Update quota and last_synced_at
  try {
    const quota = await getDriveQuota(drive, env.DB);
    await env.DB.prepare(`UPDATE drives SET quota_used = ?, quota_total = ?, last_synced_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`)
      .bind(quota.used, quota.total, drive.id).run();
  } catch (e) {}

  return { synced: totalSynced, removed: totalRemoved };
}

async function handleSync(request, env, user) {
  const body = await request.json().catch(() => ({}));
  const { drive_id } = body;
  // Manual sync should default to forceFullScan = true for 100% accuracy
  const forceFullScan = body.force_full !== false;

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

  let totalSynced  = 0;
  let totalRemoved = 0;
  const errors = [];

  for (const drive of drives) {
    try {
      const res = await performDriveSync(drive, env, forceFullScan);
      totalSynced  += res.synced;
      totalRemoved += res.removed;
    } catch (e) {
      errors.push({ drive_id: drive.id, drive_name: drive.drive_name, error: e.message });
    }
  }

  let message = `${forceFullScan ? 'Full scan' : 'Smart sync'} complete — ${totalSynced} files indexed, ${totalRemoved} removed.`;
  if (errors.length > 0) {
    message = `Error: ${errors[0].error.substring(0, 150)}`;
  }

  return jsonResponse({
    success: true,
    mode: forceFullScan ? 'full_scan' : 'smart_sync',
    synced: totalSynced,
    removed: totalRemoved,
    errors,
    message
  });
}

// ── MEDIA ───────────────────────────────────────────────────


async function handleListMedia(request, env, user) {
  const url    = new URL(request.url);
  const search = url.searchParams.get('search') || '';
  const folderId = url.searchParams.get('folder_id') || null;
  const driveId  = url.searchParams.get('drive_id') || null;
  const sortBy   = url.searchParams.get('sort_by') || 'title';
  const sortDir  = (url.searchParams.get('sort_dir') || 'asc').toUpperCase() === 'DESC' ? 'DESC' : 'ASC';
  const page     = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
  const limit    = Math.min(200, parseInt(url.searchParams.get('limit') || '50'));
  const offset   = (page - 1) * limit;

  const validSorts = { title: 'v.title', size: 'v.size', views: 'v.views', downloads: 'v.downloads', created_at: 'v.created_at', modified: 'v.drive_modified_at', resolution: 'v.resolution' };
  const orderCol = validSorts[sortBy] || 'v.title';

  let whereClause = 'WHERE v.user_id = ?';
  const bindings = [user.sub];

  if (driveId) {
    whereClause += ' AND v.drive_id = ?';
    bindings.push(parseInt(driveId));
  }

  if (folderId) {
    const targetFid = parseInt(folderId);
    const allUserFolders = await env.DB.prepare(
      'SELECT id, parent_id FROM folders WHERE user_id = ?'
    ).bind(user.sub).all();

    const getFolderAndSubfolderIds = (rootId) => {
      let ids = [rootId];
      const children = (allUserFolders.results || []).filter(f => f.parent_id === rootId);
      for (const child of children) {
        ids = ids.concat(getFolderAndSubfolderIds(child.id));
      }
      return ids;
    };

    const targetFolderIds = getFolderAndSubfolderIds(targetFid);
    const placeholders = targetFolderIds.map(() => '?').join(',');
    whereClause += ` AND v.folder_id IN (${placeholders})`;
    bindings.push(...targetFolderIds);
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

async function handleUpdateFolder(folderId, request, env, user) {
  const { name, parent_id, color } = await request.json().catch(() => ({}));
  if (!name) return errorResponse('Folder name is required.');

  const folder = await env.DB.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?')
    .bind(folderId, user.sub).first();
  if (!folder) return errorResponse('Folder not found.', 404);

  if (parent_id && parent_id === folderId) {
    return errorResponse('Folder cannot be its own parent.');
  }

  await env.DB.prepare(
    `UPDATE folders SET name = ?, parent_id = ?, color = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?`
  ).bind(name, parent_id || null, color || '#6366f1', folderId, user.sub).run();

  return jsonResponse({ success: true });
}

async function handleDeleteFolder(folderId, env, user) {
  const folder = await env.DB.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?')
    .bind(folderId, user.sub).first();
  if (!folder) return errorResponse('Folder not found.', 404);

  // Unlink videos in this folder
  await env.DB.prepare('UPDATE videos SET folder_id = NULL WHERE folder_id = ? AND user_id = ?')
    .bind(folderId, user.sub).run();

  // Reset parent_id for any subfolders of this folder to NULL
  await env.DB.prepare('UPDATE folders SET parent_id = NULL WHERE parent_id = ? AND user_id = ?')
    .bind(folderId, user.sub).run();

  // Delete folder
  await env.DB.prepare('DELETE FROM folders WHERE id = ? AND user_id = ?')
    .bind(folderId, user.sub).run();

  return jsonResponse({ success: true });
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

function extractGDriveFileId(urlStr) {
  try {
    const matchPath = urlStr.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
    if (matchPath) return matchPath[1];
    const matchQuery = urlStr.match(/[?&]id=([a-zA-Z0-9_-]+)/);
    if (matchQuery) return matchQuery[1];
    return null;
  } catch {
    return null;
  }
}

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
      const gdriveFileId = extractGDriveFileId(remoteUrl);

      // Handle Google Drive source links via fast server-side GDrive Copy
      if (gdriveFileId) {
        let gName = `gdrive_${gdriveFileId}.mp4`;
        let gMime = 'video/mp4';
        try {
          const metaResp = await fetch(`${GOOGLE_DRIVE_API}/files/${gdriveFileId}?fields=id,name,mimeType&supportsAllDrives=true`, {
            headers: { Authorization: `Bearer ${accessToken}` }
          });
          if (metaResp.ok) {
            const meta = await metaResp.json();
            if (meta.name) gName = meta.name;
            if (meta.mimeType) gMime = meta.mimeType;
          }
        } catch (_) {}

        const filename = title_prefix
          ? `${title_prefix}_${String(i + 1).padStart(3, '0')}.${gName.split('.').pop() || 'mp4'}`
          : gName;

        const copyResp = await fetch(`${GOOGLE_DRIVE_API}/files/${gdriveFileId}/copy?supportsAllDrives=true`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name: filename,
            ...(drive.root_folder_id ? { parents: [drive.root_folder_id] } : {}),
          }),
        });

        if (!copyResp.ok) throw new Error(`GDrive file copy failed: ${await copyResp.text()}`);
        const copyData = await copyResp.json();

        await env.DB.prepare(
          `INSERT INTO videos (user_id, drive_id, folder_id, drive_file_id, title, mime_type)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(drive_file_id) DO NOTHING`
        ).bind(user.sub, drive.id, folder_id ? parseInt(folder_id) : null, copyData.id, filename, gMime).run();

        results.push({ url: remoteUrl, status: 'success', drive_file_id: copyData.id, filename });
        continue;
      }

      // Handle Direct HTTP/HTTPS Video Links
      const remoteResp = await fetch(remoteUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
          'Accept': '*/*'
        }
      });
      if (!remoteResp.ok) throw new Error(`Failed to fetch remote URL: HTTP ${remoteResp.status}`);

      const contentType = remoteResp.headers.get('content-type') || 'video/mp4';
      const contentLength = remoteResp.headers.get('content-length');
      const filename = title_prefix
        ? `${title_prefix}_${String(i + 1).padStart(3, '0')}.mp4`
        : (remoteUrl.split('/').pop().split('?')[0] || `video_${Date.now()}.mp4`);

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

      // Stream body directly to Google Drive
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
      ).bind(user.sub, drive.id, folder_id ? parseInt(folder_id) : null, fileData.id, filename, contentType).run();

      results.push({ url: remoteUrl, status: 'success', drive_file_id: fileData.id, filename });
    } catch (e) {
      results.push({ url: remoteUrl, status: 'error', error: e.message });
    }
  }

  return jsonResponse({ success: true, results });
}

async function handleUploadSession(request, env, user, driveId) {
  const { filename, mimeType, folder_id, contentLength } = await request.json().catch(() => ({}));
  if (!filename || !mimeType) return errorResponse('filename and mimeType are required');

  const drive = await env.DB.prepare('SELECT * FROM drives WHERE id = ? AND user_id = ?')
    .bind(driveId, user.sub).first();
  if (!drive) return errorResponse('Drive not found.', 404);

  const accessToken = await getAccessToken(drive, env.DB);

  const initResp = await fetch(`${GOOGLE_UPLOAD_API}/files?uploadType=resumable&supportsAllDrives=true`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'X-Upload-Content-Type': mimeType,
      ...(contentLength ? { 'X-Upload-Content-Length': contentLength } : {}),
    },
    body: JSON.stringify({
      name: filename,
      mimeType: mimeType,
      ...(drive.root_folder_id ? { parents: [drive.root_folder_id] } : {}),
    }),
  });

  if (!initResp.ok) return errorResponse(`GDrive resumable init failed: ${await initResp.text()}`);
  const uploadUrl = initResp.headers.get('Location');
  
  return jsonResponse({ success: true, uploadUrl });
}

async function handleUploadComplete(request, env, user, driveId) {
  const { drive_file_id, folder_id, title, mime_type } = await request.json().catch(() => ({}));
  if (!drive_file_id || !title) return errorResponse('drive_file_id and title are required');

  await env.DB.prepare(
    `INSERT INTO videos (user_id, drive_id, folder_id, drive_file_id, title, mime_type)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(drive_file_id) DO NOTHING`
  ).bind(user.sub, driveId, folder_id || null, drive_file_id, title, mime_type).run();

  return jsonResponse({ success: true });
}

// ── EMBED / STREAM ───────────────────────────────────────────

async function handleEmbed(fileId, request, env) {
  // Increment view count (fire-and-forget)
  env.DB.prepare(
    `UPDATE videos SET views = views + 1, updated_at = datetime('now') WHERE drive_file_id = ? OR id = ?`
  ).bind(fileId, parseInt(fileId) || 0).run().catch(() => {});

  // Find the drive credentials for this file (supports both drive_file_id and v.id)
  const video = await env.DB.prepare(
    `SELECT v.*, d.client_id, d.client_secret, d.refresh_token, d.access_token, d.token_expires_at, d.id as drive_row_id
     FROM videos v JOIN drives d ON d.id = v.drive_id WHERE v.drive_file_id = ? OR v.id = ?`
  ).bind(fileId, parseInt(fileId) || 0).first();

  if (!video) {
    return new Response('Video not found.', { status: 404, headers: HTML_HEADERS });
  }

  // Build clean relative stream URL using video ID
  const streamUrl = `/stream/${video.id}`;


  const html = buildEmbedPage(video, streamUrl, video.drive_file_id);
  return new Response(html, { 
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Access-Control-Allow-Origin': '*',
      'Content-Security-Policy': 'frame-ancestors *;',
    } 
  });
}

async function handleStream(fileId, request, env) {
  const video = await env.DB.prepare(
    `SELECT v.*, d.client_id, d.client_secret, d.refresh_token, d.access_token, d.token_expires_at, d.id as drive_row_id
     FROM videos v JOIN drives d ON d.id = v.drive_id WHERE v.drive_file_id = ? OR v.id = ?`
  ).bind(fileId, parseInt(fileId) || 0).first();

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

  const driveStreamUrl = `${GOOGLE_DRIVE_API}/files/${video.drive_file_id}?alt=media&confirm=t&acknowledgeAbuse=true&supportsAllDrives=true`;

  // 1. Fetch from Google Drive API with redirect: 'manual'
  let rangeHeader = request.headers.get('Range');
  
  if (rangeHeader && rangeHeader.startsWith('bytes=-')) {
    const suffixStr = rangeHeader.substring(7);
    const suffix = parseInt(suffixStr, 10);
    const sizeNum = parseInt(video.size, 10);
    if (!isNaN(suffix) && !isNaN(sizeNum) && sizeNum > 0) {
      const start = Math.max(0, sizeNum - suffix);
      rangeHeader = `bytes=${start}-${sizeNum - 1}`;
    }
  }

  let currentUrl = driveStreamUrl;
  let driveResp;
  let redirectCount = 0;
  let reqHeaders = { Authorization: `Bearer ${accessToken}` };
  if (rangeHeader) reqHeaders['Range'] = rangeHeader;

  // Manual redirect loop to preserve Range headers (fetch 'follow' drops them on 2nd redirect)
  while (redirectCount < 5) {
    driveResp = await fetch(currentUrl, {
      method: request.method === 'HEAD' ? 'HEAD' : 'GET',
      headers: reqHeaders,
      redirect: 'manual'
    });

    if ([301, 302, 303, 307, 308].includes(driveResp.status)) {
      const location = driveResp.headers.get('Location');
      if (location) {
        currentUrl = location;
        redirectCount++;
        // Remove Authorization for googleusercontent.com to avoid 401
        reqHeaders = {};
        if (rangeHeader) reqHeaders['Range'] = rangeHeader;
        continue;
      }
    }
    break; // Break if not a redirect or no Location header
  }

  // If GDrive returned 401 (token expired), force refresh token & retry stream
  if (driveResp.status === 401) {
    try {
      const refreshedToken = await getAccessToken(fakeDrive, env.DB, true);
      currentUrl = driveStreamUrl;
      reqHeaders = { Authorization: `Bearer ${refreshedToken}` };
      if (rangeHeader) reqHeaders['Range'] = rangeHeader;
      redirectCount = 0;
      while (redirectCount < 5) {
        driveResp = await fetch(currentUrl, {
          method: request.method === 'HEAD' ? 'HEAD' : 'GET',
          headers: reqHeaders,
          redirect: 'manual'
        });
        if ([301, 302, 303, 307, 308].includes(driveResp.status)) {
          const loc = driveResp.headers.get('Location');
          if (loc) {
            currentUrl = loc;
            redirectCount++;
            reqHeaders = {};
            if (rangeHeader) reqHeaders['Range'] = rangeHeader;
            continue;
          }
        }
        break;
      }
    } catch (_) {}
  }

  // 3. Forward the response back to the client
  const responseHeaders = new Headers();
  const copyHeaders = ['Content-Length', 'Content-Range'];
  for (const h of copyHeaders) {
    const v = driveResp.headers.get(h);
    if (v) responseHeaders.set(h, v);
  }
  // Force Accept-Ranges so FFmpeg knows it can seek (Google Drive sometimes omits this header)
  responseHeaders.set('Accept-Ranges', 'bytes');
  responseHeaders.set('Content-Type', video.mime_type || driveResp.headers.get('Content-Type') || 'application/octet-stream');

  // Must add CORP for WebAssembly / SharedArrayBuffer isolation
  responseHeaders.set('Cross-Origin-Resource-Policy', 'cross-origin');
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  responseHeaders.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Disposition');

  // Disable caching entirely for the stream proxy to prevent Cloudflare from buffering
  // large files and prematurely terminating the connection with "Timeout at 0"
  responseHeaders.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');

  const url = new URL(request.url);
  const isDownload = url.searchParams.get('download') === '1' || url.searchParams.get('dl') === '1';
  const safeFilename = (video.title || 'video.mp4').replace(/"/g, '\\"');
  const encodedFilename = encodeURIComponent(video.title || 'video.mp4');
  const dispositionType = isDownload ? 'attachment' : 'inline';

  responseHeaders.set('Content-Disposition', `${dispositionType}; filename="${safeFilename}"; filename*=UTF-8''${encodedFilename}`);

  return new Response(driveResp.body, {
    status: driveResp.status,
    headers: responseHeaders,
  });
}

// ── AUTO-SYNC SETTINGS ──────────────────────────────────────

async function handleGetAutoSync(env) {
  const rows = await env.DB.prepare(
    `SELECT key, value FROM app_settings WHERE key IN ('auto_sync_enabled','auto_sync_interval_minutes','last_auto_sync_at')`
  ).all();
  const s = {};
  for (const r of rows.results) s[r.key] = r.value;
  return jsonResponse({
    success: true,
    auto_sync_enabled:          s.auto_sync_enabled          === '1',
    auto_sync_interval_minutes: parseInt(s.auto_sync_interval_minutes || '30'),
    last_auto_sync_at:          s.last_auto_sync_at || null,
  });
}

async function handleSetAutoSync(request, env) {
  const body = await request.json().catch(() => ({}));
  const stmts = [];

  if (typeof body.auto_sync_enabled === 'boolean') {
    stmts.push(env.DB.prepare(
      `INSERT INTO app_settings (key,value,updated_at) VALUES ('auto_sync_enabled',?,datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
    ).bind(body.auto_sync_enabled ? '1' : '0'));
  }
  if ([30, 60, 120].includes(body.auto_sync_interval_minutes)) {
    stmts.push(env.DB.prepare(
      `INSERT INTO app_settings (key,value,updated_at) VALUES ('auto_sync_interval_minutes',?,datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
    ).bind(String(body.auto_sync_interval_minutes)));
  }

  if (stmts.length) await env.DB.batch(stmts);
  return jsonResponse({ success: true, message: 'Auto-sync settings updated.' });
}

// ── SINGLE VIDEO ─────────────────────────────────────────────

async function handleGetVideo(videoId, env, user) {
  const video = await env.DB.prepare(
    `SELECT v.id, v.drive_file_id, v.title, v.size, v.resolution, v.duration,
            v.views, v.downloads, v.mime_type, v.thumbnail_url, v.folder_id,
            v.is_public, v.tags, v.drive_modified_at, v.created_at,
            d.drive_name
     FROM videos v LEFT JOIN drives d ON d.id = v.drive_id
     WHERE v.id = ? AND v.user_id = ?`
  ).bind(videoId, user.sub).first();
  if (!video) return errorResponse('Video not found.', 404);
  return jsonResponse({ success: true, video });
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
    `SELECT id, drive_file_id, title, views, downloads, size, resolution
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
  const mime     = (video.mime_type || '').toLowerCase();
  const titleLow = (video.title    || '').toLowerCase();
  const isMp4    = (mime === 'video/mp4' || mime === 'video/m4v') && !titleLow.includes('.mkv');
  const isHeavy  = !isMp4 ||
                   mime.includes('matroska') || mime.includes('mkv') || mime.includes('octet-stream') ||
                   titleLow.includes('mkv') || titleLow.includes('hevc') || titleLow.includes('x265') ||
                   titleLow.includes('h.265') || titleLow.includes('10bit') || titleLow.includes('av1');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>${escapeHtml(video.title)} — HaruStream PRO</title>
  <meta name="robots" content="noindex">
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html,body{width:100vw;height:100vh;background:#000;overflow:hidden;margin:0;padding:0;}
    #artplayer-container{position:absolute;top:0;left:0;width:100vw;height:100vh;display:block;}
    .art-video-player{background:#000;width:100%;height:100%;}
    video{object-fit:contain !important;width:100% !important;height:100% !important;}

    /* ── Warning Modal ─────────────────────────────────── */
    #warn-modal {
      position:fixed;inset:0;z-index:9999;
      background:#0b0b14;
      display:flex;align-items:center;justify-content:center;
      padding:8px;
    }
    .warn-box {
      background:linear-gradient(135deg,#141428,#1a1a36);
      border:1px solid rgba(99,102,241,0.35);
      border-radius:14px;padding:12px 16px;
      max-width:500px;width:96%;text-align:center;margin:auto;
      box-shadow:0 24px 60px rgba(0,0,0,0.9);
      animation:warnIn .3s ease-out;
      box-sizing:border-box;
    }
    @keyframes warnIn{from{opacity:0;transform:scale(.92) translateY(12px)}to{opacity:1;transform:scale(1) translateY(0)}}
    .warn-icon{
      width:36px;height:36px;border-radius:50%;
      background:linear-gradient(135deg,rgba(239,68,68,.2),rgba(245,158,11,.15));
      border:1.5px solid rgba(239,68,68,.4);
      display:flex;align-items:center;justify-content:center;
      margin:0 auto 6px;
    }
    .warn-icon svg{width:20px;height:20px;}
    .warn-title{font-size:14px;font-weight:700;color:#fff;margin-bottom:4px;font-family:Inter,sans-serif}
    .warn-body{font-size:11.5px;line-height:1.4;color:#94a3b8;font-family:Inter,sans-serif;margin-bottom:8px}
    .warn-ext-group{display:flex;flex-direction:column;gap:4px}
    .warn-ext-btn{
      display:flex;align-items:center;gap:8px;
      padding:6px 12px;border-radius:8px;border:1px solid rgba(99,102,241,0.35);
      background:rgba(99,102,241,0.12);color:#a5b4fc;
      font-size:11.5px;font-weight:600;cursor:pointer;
      text-align:left;transition:all .15s;
      font-family:Inter,sans-serif;
    }
    .warn-ext-btn:hover{background:rgba(99,102,241,0.28);color:#c7d2fe}
    .warn-ext-btn svg{width:14px;height:14px;flex-shrink:0;opacity:.85}
    .warn-force-btn{
      width:100%;padding:6px 12px;border-radius:8px;
      background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
      color:#64748b;font-size:11.5px;font-weight:600;cursor:pointer;
      transition:all .15s;font-family:Inter,sans-serif;
    }
    .warn-force-btn:hover{background:rgba(255,255,255,0.08);color:#94a3b8}

    @media (max-height: 440px), (max-width: 480px) {
      .warn-box { padding: 8px 10px; border-radius: 10px; }
      .warn-icon { width: 28px; height: 28px; margin-bottom: 4px; }
      .warn-icon svg { width: 16px; height: 16px; }
      .warn-title { font-size: 12px; margin-bottom: 2px; }
      .warn-body { font-size: 10px; margin-bottom: 4px; }
      .warn-ext-btn, .warn-force-btn { padding: 4px 8px; font-size: 10px; border-radius: 6px; }
    }

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
  <script>
    function copyStreamLink(e, url) {
      if (e && e.preventDefault) e.preventDefault();
      const absoluteUrl = new URL(url, window.location.origin).href;
      let copied = false;
      const doSuccess = () => {
        const txt = document.getElementById('copy-txt');
        if (txt) {
          const old = txt.innerText;
          txt.innerText = '✔ Link Streaming Tersalin!';
          setTimeout(() => txt.innerText = old, 2500);
        }
      };

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(absoluteUrl).then(doSuccess).catch(() => fallbackCopy(absoluteUrl));
      } else {
        fallbackCopy(absoluteUrl);
      }

      function fallbackCopy(text) {
        try {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none;z-index:-1;';
          document.body.appendChild(ta);
          ta.focus({ preventScroll: true });
          ta.select();
          copied = document.execCommand('copy');
          document.body.removeChild(ta);
        } catch (err) {}

        if (copied) {
          doSuccess();
        } else {
          prompt('Salin link streaming di bawah ini (Ctrl+C):', text);
        }
      }
    }

    function openExternal(player, streamUrl, title) {
      let absoluteUrl = new URL(streamUrl, window.location.origin).href;
      const encodedTitle = encodeURIComponent(title || 'video.mkv');
      // Tambahkan param download=1 agar Content-Disposition memunculkan nama file
      if (!absoluteUrl.includes('download=1')) {
          absoluteUrl += (absoluteUrl.includes('?') ? '&' : '?') + 'download=1';
      }

      let urlWithoutProto = absoluteUrl.split('://')[1] || absoluteUrl;
      if (player === 'potplayer') {
        window.location.href = 'potplayer://' + absoluteUrl;
      } else if (player === 'vlc') {
        if (/android/i.test(navigator.userAgent)) {
          window.location.href = 'intent://' + urlWithoutProto + '#Intent;scheme=https;package=org.videolan.vlc;S.title=' + encodedTitle + ';type=video/*;end';
        } else {
          window.location.href = 'vlc://' + absoluteUrl;
        }
      } else if (player === 'mx') {
        window.location.href = 'intent://' + urlWithoutProto + '#Intent;scheme=https;package=com.mxtech.videoplayer.ad;S.title=' + encodedTitle + ';type=video/*;end';
      }
    }

    function toggleExtMenu() {
      const d = document.getElementById('ext-dropdown');
      if (d) d.classList.toggle('open');
    }

    // This will be called by the force button
    function dismissWarningAndPlay(mode) {
      const modal = document.getElementById('warn-modal');
      if (modal) modal.style.display = 'none';
      const container = document.getElementById('artplayer-container');
      if (container) container.style.display = 'block';
      if (typeof window.initPlayer === 'function') {
        window.initPlayer(mode);
      }
    }

    document.addEventListener('click', (e) => {
      const wrap = document.getElementById('ext-menu-wrap');
      if (wrap && !wrap.contains(e.target)) {
        const d = document.getElementById('ext-dropdown');
        if (d) d.classList.remove('open');
      }
    });
  </script>
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
      <div class="warn-title">⚠ Format Berat Terdeteksi (MKV/Multi-track)</div>
      
      <div class="warn-body" style="text-align: left; margin-bottom: 12px; font-size: 13px;">
        Pilih mode pemutaran di bawah ini:
      </div>

      <div class="warn-ext-group">
        <div style="text-align:left; font-size:12px; color:#a5b4fc; margin-bottom:4px; font-weight:600;">Opsi 1: Aplikasi Eksternal (100% Lancar)</div>
        <button type="button" class="warn-ext-btn" onclick="copyStreamLink(event, '${streamUrl}')">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="#a5b4fc"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
          <span id="copy-txt">Copy Link Streaming (Untuk VLC Desktop CTRL+N)</span>
        </button>
        <div style="display:flex; gap:6px;">
            <button class="warn-ext-btn" style="flex:1; justify-content:center; padding:10px 4px; font-size:12px;" onclick="openExternal('potplayer', '${streamUrl}', ${JSON.stringify(video.title).replace(/"/g, '&quot;')})">PotPlayer</button>
            <button class="warn-ext-btn" style="flex:1; justify-content:center; padding:10px 4px; font-size:12px;" onclick="openExternal('vlc', '${streamUrl}', ${JSON.stringify(video.title).replace(/"/g, '&quot;')})">VLC Mobile</button>
            <button class="warn-ext-btn" style="flex:1; justify-content:center; padding:10px 4px; font-size:12px;" onclick="openExternal('mx', '${streamUrl}', ${JSON.stringify(video.title).replace(/"/g, '&quot;')})">MX Player</button>
        </div>

        <div style="text-align:left; font-size:12px; color:#a5b4fc; margin-top:12px; margin-bottom:4px; font-weight:600;">Opsi 2: Movi-Player (Multi-Audio & Subs Native)</div>
        <button class="warn-force-btn" style="text-align:left; color:#e2e8f0; background:rgba(99,102,241,0.2); border-color:rgba(99,102,241,0.4);" onclick="dismissWarningAndPlay('movi')">
          ▶ Putar (Tanpa Style ASS Berat)
        </button>
        
        <div style="text-align:left; font-size:12px; color:#a5b4fc; margin-top:12px; margin-bottom:4px; font-weight:600;">Opsi 3: Artplayer (Video & Audio Utama)</div>
        <button class="warn-force-btn" style="text-align:left; color:#e2e8f0; background:rgba(99,102,241,0.1); border-color:rgba(99,102,241,0.2);" onclick="dismissWarningAndPlay('art')">
          ▶ Putar (Tanpa Subtitle ASS & Multi-Audio)
        </button>
      </div>
    </div>
  </div>` : ''}

  <div id="artplayer-container" style="${isHeavy ? 'display:none;' : ''}"></div>

  <script src="https://cdn.jsdelivr.net/npm/artplayer@5/dist/artplayer.js"></script>
  ${isHeavy ? `
  <script type="module" src="https://cdn.jsdelivr.net/npm/movi-player@0.3.5/dist/element.js"></script>
  ` : ''}

  <script>
    const videoTitle  = ${JSON.stringify(video.title)};
    const streamUrl   = ${JSON.stringify(streamUrl)};
    const driveFileId = ${JSON.stringify(driveFileId)};
    const isHeavy     = ${isHeavy ? 'true' : 'false'};

    // ── Initialize the player ────────────────────────────────
    let art = null;
    let wasmPlayerActive = false;

    window.initPlayer = function(mode) {
      if (mode === 'movi') {
        const container = document.getElementById('artplayer-container');
        container.innerHTML = '<movi-player src="' + streamUrl + '" style="width:100%;height:100%;display:block;" controls></movi-player>';
        const playerEl = container.querySelector('movi-player');
        
        // Add Retry button on error
        function showRetry() {
            if (document.getElementById('retry-btn')) return;
            const errDiv = document.createElement('div');
            errDiv.id = 'retry-btn';
            errDiv.style.position = 'absolute';
            errDiv.style.top = '65%';
            errDiv.style.left = '50%';
            errDiv.style.transform = 'translate(-50%, -50%)';
            errDiv.style.zIndex = '999999';
            errDiv.innerHTML = '<button onclick="window.location.reload()" style="padding:12px 24px; background:#e74c3c; color:white; border:none; border-radius:8px; font-weight:bold; cursor:pointer; font-size:16px; box-shadow: 0 4px 6px rgba(0,0,0,0.3);">🔄 Timeout - Klik Untuk Retry</button>';
            container.appendChild(errDiv);
        }
        
        let errorPoll = setInterval(() => {
            if (playerEl.shadowRoot) {
                const html = playerEl.shadowRoot.innerHTML;
                if (html.includes('Failed to open media') || html.includes('Timeout') || html.includes('Initialization Failed')) {
                    showRetry();
                    clearInterval(errorPoll);
                }
            }
        }, 1000);
        return;
      }

      if (art) {
        art.play().catch(e => console.error(e));
        return;
      }
      art = new Artplayer({
        container: '#artplayer-container',
        url:       streamUrl,
        title:     videoTitle,
        autoplay:  false, // Disabled per user request
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
        autoSize: false,
        autoMini: false,
        theme: '#6366f1',
        lang: 'en',
        moreVideoAttr: {
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
                  '<div class="ext-item" onclick="openExternal(&quot;potplayer&quot;, &quot;${streamUrl}&quot;)">' +
                  '<svg width="14" height="14" viewBox="0 0 24 24" fill="#a5b4fc"><path d="M8 5v14l11-7z"/></svg>PotPlayer (Windows)</div>' +
                  '<div class="ext-item" onclick="openExternal(&quot;vlc&quot;, &quot;${streamUrl}&quot;)">' +
                  '<svg width="14" height="14" viewBox="0 0 24 24" fill="#a5b4fc"><path d="M8 5v14l11-7z"/></svg>VLC (Cross-platform)</div>' +
                  '<div class="ext-item" onclick="openExternal(&quot;mx&quot;, &quot;${streamUrl}&quot;)">' +
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
      // ── Error tracking ───────────────────────────────────
      art.on('error', (error, detail) => {
        console.error('[HaruStream] ArtPlayer error:', error, detail);
      });
    }; // end initPlayer()

    // ── Startup logic ─────────────────────────────────────
    if (isHeavy) {
      // Heavy format: show the warning modal with 3 options
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

function formatBytes(bytes, decimals = 2) {
  if (!bytes || isNaN(bytes) || bytes <= 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

async function handleExportTelegraph(request, env) {
  try {
    const body = await request.json().catch(() => ({}));
    const { title, items } = body;

    if (!items || !Array.isArray(items) || items.length === 0) {
      return errorResponse('No items to export.', 400);
    }

    // 1. Get or create Telegra.ph account token
    let accessToken;
    const accResp = await fetch('https://api.telegra.ph/createAccount?short_name=HaruStream&author_name=HaruStream');
    const accData = await accResp.json();
    if (accData.ok && accData.result?.access_token) {
      accessToken = accData.result.access_token;
    } else {
      return errorResponse('Failed to create Telegra.ph session', 500);
    }

    // 2. Build Telegra.ph Node Array for ALL items
    const contentNodes = [];
    const exportItems = items.slice(0, 500); // Max 500 items per Telegra.ph page

    for (let i = 0; i < exportItems.length; i++) {
      const item = exportItems[i];
      if (!item) continue;

      if (item.title) {
        contentNodes.push({ tag: 'h4', children: [ item.title ] });
      }

      const metaParts = [];
      if (item.resolution) metaParts.push(`Resolution: ${item.resolution}`);
      if (item.size) {
        const sizeStr = typeof item.size === 'number' ? formatBytes(item.size) : String(item.size);
        metaParts.push(`Size: ${sizeStr}`);
      }
      if (item.views !== undefined && item.views !== null && item.views !== '') {
        metaParts.push(`Views: ${item.views}`);
      }

      if (metaParts.length > 0) {
        contentNodes.push({ tag: 'p', children: [{ tag: 'em', children: [ metaParts.join(' | ') ] }] });
      }

      if (item.downloadLink) {
        contentNodes.push({
          tag: 'p',
          children: [
            '📥 Download: ',
            { tag: 'a', attrs: { href: item.downloadLink }, children: [ item.downloadLink ] }
          ]
        });
      }

      if (item.streamLink) {
        contentNodes.push({
          tag: 'p',
          children: [
            '▶ Stream: ',
            { tag: 'a', attrs: { href: item.streamLink }, children: [ item.streamLink ] }
          ]
        });
      }

      if (item.embedLink) {
        contentNodes.push({
          tag: 'p',
          children: [
            '🎬 Embed Link: ',
            { tag: 'a', attrs: { href: item.embedLink }, children: [ item.embedLink ] }
          ]
        });
      }

      if (item.embedCode) {
        contentNodes.push({
          tag: 'p',
          children: [
            '💻 Embed Code: ',
            { tag: 'code', children: [ item.embedCode ] }
          ]
        });
      }

      if (i < exportItems.length - 1) {
        contentNodes.push({ tag: 'hr' });
      }
    }

    const pageTitle = (title || 'HaruStream Export').substring(0, 250);
    const pageResp = await fetch('https://api.telegra.ph/createPage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_token: accessToken,
        title: pageTitle,
        content: contentNodes,
        return_content: false
      })
    });

    const pageData = await pageResp.json();
    if (pageData.ok && pageData.result?.url) {
      return jsonResponse({ success: true, url: pageData.result.url, count: exportItems.length });
    } else {
      return errorResponse(`Telegra.ph API Error: ${pageData.error || 'Unknown error'}`, 500);
    }
  } catch (e) {
    return errorResponse(`Telegra.ph export error: ${e.message}`, 500);
  }
}

// ── CRON SCHEDULED HANDLER ────────────────────────────────────
// Runs every 1 minute via Cloudflare Cron Triggers.
// Cost: 1 D1 read per minute when idle (~1440 reads/day).
// Only runs actual sync when: enabled AND (now - last_sync) >= interval.

async function runAutoSync(env) {
  // ── 1. Read settings (1 D1 read) ────────────────────────────
  const rows = await env.DB.prepare(
    `SELECT key, value FROM app_settings WHERE key IN ('auto_sync_enabled','auto_sync_interval_minutes','last_auto_sync_at')`
  ).all();

  const s = {};
  for (const r of rows.results) s[r.key] = r.value;

  if (s.auto_sync_enabled !== '1') return; // disabled → bail immediately

  const intervalMs   = parseInt(s.auto_sync_interval_minutes || '30') * 60 * 1000;
  const lastSyncTime = new Date(s.last_auto_sync_at || 0).getTime();
  const now          = Date.now();

  if (now - lastSyncTime < intervalMs) return; // not yet time → bail

  // ── 2. Time to sync! Get all active drives ───────────────────
  const drivesResult = await env.DB.prepare(
    `SELECT * FROM drives WHERE is_active = 1`
  ).all();
  const drives = drivesResult.results;
  if (!drives.length) return;

  // ── 3. Perform sync for each drive ───────────────────────────
  for (const drive of drives) {
    try {
      await performDriveSync(drive, env, false);
    } catch (e) {
      console.error(`Auto-sync error for drive ${drive.id}:`, e);
    }
  }

  // ── 4. Update last_auto_sync_at ─────────────────────────────
  await env.DB.prepare(
    `INSERT INTO app_settings (key,value,updated_at) VALUES ('last_auto_sync_at',?,datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
  ).bind(new Date().toISOString()).run();
}

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
      const parts = path.split('/').filter(Boolean); // ['embed', '123']
      if (parts.length < 2) return errorResponse('Not Found', 404);
      return await handleEmbed(parts[1], request, env);
    }

    if ((method === 'GET' || method === 'HEAD') && path.startsWith('/stream/')) {
      const parts = path.split('/').filter(Boolean); // ['stream', '123', 'filename.mkv']
      if (parts.length < 2) return errorResponse('Not Found', 404);
      return await handleStream(parts[1], request, env);
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
    else if (path.startsWith('/api/folders/') && method === 'PUT') {
      const folderId = parseInt(path.split('/').pop());
      res = await handleUpdateFolder(folderId, request, env, user);
    }
    else if (path.startsWith('/api/folders/') && method === 'DELETE') {
      const folderId = parseInt(path.split('/').pop());
      res = await handleDeleteFolder(folderId, env, user);
    }

    // Remote upload
    else if (path === '/api/media/upload/remote' && method === 'POST') {
      res = await handleRemoteUpload(request, env, user);
    }
    
    // Device upload session
    else if (path.match(/^\/api\/drives\/\d+\/upload-session$/) && method === 'POST') {
      const driveId = parseInt(path.split('/')[3]);
      res = await handleUploadSession(request, env, user, driveId);
    }
    // Device upload complete
    else if (path.match(/^\/api\/drives\/\d+\/upload-complete$/) && method === 'POST') {
      const driveId = parseInt(path.split('/')[3]);
      res = await handleUploadComplete(request, env, user, driveId);
    }

    // Stats
    else if (path === '/api/stats' && method === 'GET') {
      res = await handleStats(env, user);
    }

    // Me
    else if (path === '/api/auth/me' && method === 'GET') {
      res = jsonResponse({ success: true, user: { id: user.sub, username: user.username, role: user.role } });
    }

    // Export Telegra.ph
    else if (path === '/api/export/telegraph' && method === 'POST') {
      res = await handleExportTelegraph(request, env);
    }

    // Auto-sync settings
    else if (path === '/api/settings/auto-sync') {
      if (method === 'GET')       res = await handleGetAutoSync(env);
      else if (method === 'POST') res = await handleSetAutoSync(request, env);
      else res = errorResponse('Method not allowed.', 405);
    }

    // Single video detail
    else if (path.startsWith('/api/media/') && method === 'GET') {
      const videoId = parseInt(path.split('/').pop());
      if (!isNaN(videoId)) res = await handleGetVideo(videoId, env, user);
      else res = errorResponse('Not Found.', 404);
    }

    // Fallthrough → serve public SPA (handled by Cloudflare Pages)
    else {
      res = errorResponse('Not Found.', 404);
    }

    addCorsHeaders(res, corsHeaders);
    return res;
  },

  // ── Cron handler (1-minute interval, smart sleep) ─────────
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(runAutoSync(env));
  },
};

function addCorsHeaders(res, corsHeaders) {
  if (!res) return;
  for (const [k, v] of Object.entries(corsHeaders)) {
    res.headers.set(k, v);
  }
}
