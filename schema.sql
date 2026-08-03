-- ============================================================
-- HaruStream PRO - Cloudflare D1 Database Schema
-- Version: 1.0.0
-- ============================================================

-- Drop existing tables if they exist (for clean re-init)
DROP TABLE IF EXISTS videos;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS drives;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

-- ============================================================
-- Table: users
-- Stores authenticated user accounts
-- ============================================================
CREATE TABLE users (
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
CREATE TABLE sessions (
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
-- Table: drives
-- Stores per-user Google Drive OAuth credentials
-- ============================================================
CREATE TABLE drives (
    id               INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER  NOT NULL,
    drive_name       TEXT     NOT NULL,
    client_id        TEXT     NOT NULL,
    client_secret    TEXT     NOT NULL,
    refresh_token    TEXT     NOT NULL,
    access_token     TEXT,
    token_expires_at DATETIME,
    root_folder_id   TEXT,
    quota_used       INTEGER  DEFAULT 0,
    quota_total      INTEGER  DEFAULT 0,
    last_synced_at   DATETIME,
    is_active        INTEGER  NOT NULL DEFAULT 1,
    created_at       DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at       DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================
-- Table: folders
-- 100% virtual folder tree, fully decoupled from Google Drive
-- physical layout. Supports unlimited nesting.
-- ============================================================
CREATE TABLE folders (
    id         INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER  NOT NULL,
    parent_id  INTEGER  NULL,
    name       TEXT     NOT NULL,
    color      TEXT     DEFAULT '#6366f1',
    icon       TEXT     DEFAULT 'folder',
    sort_order INTEGER  DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- ============================================================
-- Table: videos
-- Indexes Google Drive video files into the virtual library.
-- drive_file_id is the GDrive file ID and acts as a unique key.
-- ============================================================
CREATE TABLE videos (
    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER  NOT NULL,
    drive_id          INTEGER  NOT NULL,
    folder_id         INTEGER  NULL,
    drive_file_id     TEXT     NOT NULL UNIQUE,
    title             TEXT     NOT NULL,
    description       TEXT,
    thumbnail_url     TEXT,
    mime_type         TEXT     DEFAULT 'video/mp4',
    size              INTEGER  DEFAULT 0,
    duration          INTEGER  DEFAULT 0,
    resolution        TEXT,
    codec             TEXT,
    views             INTEGER  NOT NULL DEFAULT 0,
    downloads         INTEGER  NOT NULL DEFAULT 0,
    is_public         INTEGER  NOT NULL DEFAULT 0,
    custom_embed_code TEXT,
    tags              TEXT,
    drive_modified_at DATETIME,
    created_at        DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at        DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY (drive_id)  REFERENCES drives(id)  ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- ============================================================
-- Performance Indexes
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_sessions_user_id     ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash  ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_drives_user_id       ON drives(user_id);
CREATE INDEX IF NOT EXISTS idx_folders_user_id      ON folders(user_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent_id    ON folders(parent_id);
CREATE INDEX IF NOT EXISTS idx_videos_user_id       ON videos(user_id);
CREATE INDEX IF NOT EXISTS idx_videos_drive_id      ON videos(drive_id);
CREATE INDEX IF NOT EXISTS idx_videos_folder_id     ON videos(folder_id);
CREATE INDEX IF NOT EXISTS idx_videos_drive_file_id ON videos(drive_file_id);
CREATE INDEX IF NOT EXISTS idx_videos_title         ON videos(title);
CREATE INDEX IF NOT EXISTS idx_videos_views         ON videos(views);
CREATE INDEX IF NOT EXISTS idx_videos_created_at    ON videos(created_at);
