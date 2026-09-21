-- ============================================================
-- HaruStream - Cloudflare D1 Database Schema
-- Version: 1.1.0 (Multi-Cloud Storage & Permanent D1 ID Safe)
-- ============================================================

-- ============================================================
-- Table: users
-- Stores authenticated user accounts
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    username      TEXT     NOT NULL UNIQUE,
    password_hash TEXT     NOT NULL,
    email         TEXT     UNIQUE,
    role          TEXT     NOT NULL DEFAULT 'user',
    avatar_url    TEXT,
    created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- Table: sessions
-- Stores active JWT sessions / refresh tokens
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER  NOT NULL,
    token_hash TEXT     NOT NULL UNIQUE,
    user_agent TEXT,
    ip_address TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================
-- Table: drives / storage_providers
-- Stores per-user storage connections (GDrive, Hugging Face, Transfer.it)
-- ============================================================
CREATE TABLE IF NOT EXISTS drives (
    id                      INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id                 INTEGER  NOT NULL,
    drive_name              TEXT     NOT NULL,
    provider_type           TEXT     NOT NULL DEFAULT 'gdrive', -- 'gdrive', 'huggingface', 'transfer_it'
    client_id               TEXT     NULL,
    client_secret           TEXT     NULL,
    refresh_token           TEXT     NULL,
    access_token            TEXT     NULL,
    token_expires_at        DATETIME NULL,
    root_folder_id          TEXT     NULL,
    hf_repo_id              TEXT     NULL,
    hf_token                TEXT     NULL,
    hf_branch               TEXT     DEFAULT 'main',
    transfer_sid            TEXT     NULL,
    transfer_url            TEXT     NULL,
    transfer_expires_at     DATETIME NULL,
    transfer_download_count INTEGER  DEFAULT 0,
    config_json             TEXT     NULL,
    quota_used              INTEGER  DEFAULT 0,
    quota_total             INTEGER  DEFAULT 0,
    last_synced_at          DATETIME NULL,
    sync_token              TEXT     NULL,
    is_active               INTEGER  NOT NULL DEFAULT 1,
    created_at              DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at              DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================
-- Table: folders
-- 100% virtual folder tree, decoupled from physical storage layout.
-- ============================================================
CREATE TABLE IF NOT EXISTS folders (
    id                      INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id                 INTEGER  NOT NULL,
    drive_id                INTEGER  NULL,
    parent_id               INTEGER  NULL,
    provider_type           TEXT     DEFAULT 'gdrive',
    gdrive_folder_id        TEXT     NULL,
    parent_gdrive_folder_id TEXT     NULL,
    name                    TEXT     NOT NULL,
    color                   TEXT     DEFAULT '#6366f1',
    icon                    TEXT     DEFAULT 'folder',
    sort_order              INTEGER  DEFAULT 0,
    created_at              DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at              DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- ============================================================
-- Table: videos
-- Indexes files across GDrive, Hugging Face, and Transfer.it.
-- All video IDs are strictly permanent.
-- ============================================================
CREATE TABLE IF NOT EXISTS videos (
    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER  NOT NULL,
    drive_id          INTEGER  NOT NULL,
    folder_id         INTEGER  NULL,
    provider_type     TEXT     NOT NULL DEFAULT 'gdrive', -- 'gdrive', 'huggingface', 'transfer_it'
    drive_file_id     TEXT     NOT NULL UNIQUE,
    storage_uri       TEXT     NULL,
    title             TEXT     NOT NULL,
    description       TEXT     NULL,
    thumbnail_url     TEXT     NULL,
    mime_type         TEXT     DEFAULT 'video/mp4',
    size              INTEGER  DEFAULT 0,
    duration          INTEGER  DEFAULT 0,
    resolution        TEXT     NULL,
    codec             TEXT     NULL,
    views             INTEGER  NOT NULL DEFAULT 0,
    downloads         INTEGER  NOT NULL DEFAULT 0,
    is_public         INTEGER  NOT NULL DEFAULT 0,
    custom_embed_code TEXT     NULL,
    tags              TEXT     NULL,
    expires_at        DATETIME NULL,
    download_limit    INTEGER  DEFAULT 0,
    provider_downloads INTEGER DEFAULT 0,
    drive_modified_at DATETIME NULL,
    created_at        DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at        DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY (drive_id)  REFERENCES drives(id)  ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- ============================================================
-- Table: app_settings
-- ============================================================
CREATE TABLE IF NOT EXISTS app_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- Performance Indexes
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_sessions_user_id     ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash  ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_drives_user_id       ON drives(user_id);
CREATE INDEX IF NOT EXISTS idx_folders_user_id      ON folders(user_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent_id    ON folders(parent_id);
CREATE INDEX IF NOT EXISTS idx_folders_drive_id     ON folders(drive_id);
CREATE INDEX IF NOT EXISTS idx_videos_user_id       ON videos(user_id);
CREATE INDEX IF NOT EXISTS idx_videos_drive_id      ON videos(drive_id);
CREATE INDEX IF NOT EXISTS idx_videos_folder_id     ON videos(folder_id);
CREATE INDEX IF NOT EXISTS idx_videos_drive_file_id ON videos(drive_file_id);
CREATE INDEX IF NOT EXISTS idx_videos_title         ON videos(title);
CREATE INDEX IF NOT EXISTS idx_videos_views         ON videos(views);
CREATE INDEX IF NOT EXISTS idx_videos_created_at    ON videos(created_at);

-- Compound Performance Indexes (Zero Full-Table Scan)
CREATE INDEX IF NOT EXISTS idx_videos_user_views         ON videos(user_id, views DESC);
CREATE INDEX IF NOT EXISTS idx_videos_user_created       ON videos(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_videos_user_title         ON videos(user_id, title ASC);
CREATE INDEX IF NOT EXISTS idx_videos_user_folder_title  ON videos(user_id, folder_id, title ASC);
CREATE INDEX IF NOT EXISTS idx_videos_user_drive_title   ON videos(user_id, drive_id, title ASC);
CREATE INDEX IF NOT EXISTS idx_folders_user_drive        ON folders(user_id, drive_id);

