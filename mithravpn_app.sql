-- ============================================================================
-- mithravpn_app — database for the Android/iOS/Windows apps.
--
-- Scope note: this database holds the app-native tables (users, servers,
-- vpn_clients, refresh_tokens, connection_logs) PLUS `telegram_accounts`
-- and `telegram_admins`, carried over from the bot's schema so the two
-- systems can be linked or queried together. The bot's other tables
-- (payments, visit, UserKeys, wg_clients, vpn_servers) are NOT duplicated
-- here and still live only in the original `mithravpn` database — nothing
-- in this file touches or depends on that database.
--
-- Usage: run this whole file once, as a MySQL admin, to create the
-- database and every table the backend expects:
--   mysql -u <admin> -p < mithravpn_app_db.sql
-- ============================================================================

CREATE DATABASE IF NOT EXISTS mithravpn_app
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE mithravpn_app;

-- ----------------------------------------------------------------------------
-- users — one row per app account. This is what the Login/Register screen
-- reads and writes.
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username       VARCHAR(50)  NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,      -- bcrypt hash, never plaintext
    email          VARCHAR(100) DEFAULT NULL,
    first_name     VARCHAR(50)  DEFAULT NULL,
    last_name      VARCHAR(50)  DEFAULT NULL,
    is_active      TINYINT(1)   NOT NULL DEFAULT 1,
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at  DATETIME     DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email)
);

-- ----------------------------------------------------------------------------
-- servers — every VPN server the app can offer, and whether/how it's shown.
-- ----------------------------------------------------------------------------
CREATE TABLE servers (
    id                       INT NOT NULL AUTO_INCREMENT,
    name                     VARCHAR(50)  NOT NULL,   -- internal id, e.g. IR-Tehran-1
    alias                    VARCHAR(100) DEFAULT NULL, -- shown to users, e.g. "Tehran Premium"
    country                  VARCHAR(50)  NOT NULL,
    city                     VARCHAR(50)  NOT NULL,
    endpoint_international   VARCHAR(255) NOT NULL,   -- address used from outside Iran
    endpoint_iran            VARCHAR(255) NOT NULL,   -- address used from inside Iran
    outline_api_url          VARCHAR(255) DEFAULT NULL, -- Outline management API base URL (NULL for WireGuard-only servers)
    outline_cert_sha256      VARCHAR(64)  DEFAULT NULL, -- SHA-256 fingerprint of the Outline server's self-signed cert
    wireguard_port           INT DEFAULT NULL,        -- WireGuard listen port; NULL for Outline-only servers
    max_users                INT NOT NULL DEFAULT 0,
    current_users            INT NOT NULL DEFAULT 0,
    status                   ENUM('ACTIVE','INACTIVE','MAINTENANCE','FULL') NOT NULL DEFAULT 'ACTIVE',
    visible_to_app           TINYINT(1) NOT NULL DEFAULT 1,
    sort_order               INT NOT NULL DEFAULT 0,
    created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_servers_name (name),
    INDEX idx_servers_status (status),
    INDEX idx_servers_country (country)
);

-- ----------------------------------------------------------------------------
-- telegram_accounts / telegram_admins — carried over from the bot's schema
-- (originally `accounts` and `admins`), kept as their own tables since
-- Telegram IDs and app user IDs are different identity spaces. See the
-- "Bridging the two systems" note near the bottom for how to link a user
-- across both, if you ever need that.
--
-- No FK from telegram_admins.UserID to telegram_accounts.UserID is
-- defined here — matching the original bot schema, which didn't have one
-- either. That means MySQL won't stop an admin row for a UserID with no
-- matching account row. Say the word if you'd rather that be enforced.
-- ----------------------------------------------------------------------------
CREATE TABLE telegram_accounts (
    UserID BIGINT UNSIGNED PRIMARY KEY,  -- Telegram ID
    FirstName VARCHAR(50),
    LastName VARCHAR(50),
    Username VARCHAR(50),
    CurrentBalance DECIMAL(10,2) DEFAULT 0.00,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE telegram_admins (
    AdminID BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    UserID BIGINT UNSIGNED NOT NULL,
    Username VARCHAR(255) DEFAULT NULL,
    Role ENUM('superadmin', 'admin', 'moderator') DEFAULT 'admin',
    AddedAt TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    IsActive TINYINT(1) DEFAULT 1,
    PRIMARY KEY (AdminID),
    UNIQUE KEY (UserID)
);

-- ----------------------------------------------------------------------------
-- vpn_clients — one row per issued VPN credential, linking a user to a
-- server and tracking traffic. Covers BOTH protocols you run:
--   - WireGuard peers
--   - Outline / Shadowsocks access keys (merged in from the bot's old
--     UserKeys table, which was Outline-only)
--
-- Merge notes (read before writing backend code against this table):
--   - `protocol` says which set of columns is populated. The CHECK
--     constraint enforces that a 'wireguard' row has public_key+address,
--     and an 'outline' row has full_key. (CHECK constraints are enforced
--     on MySQL 8.0.16+; on older MySQL the syntax is accepted but
--     silently not enforced — the application layer should still
--     validate either way.)
--   - rx_bytes/tx_bytes are nullable: they start out NULL until a usage
--     poll reports real numbers. Because MySQL generated columns
--     propagate NULL, total_bytes (rx_bytes + tx_bytes) is also NULL
--     until BOTH are populated — SUM() across rows ignores NULLs
--     correctly, but any code that reads total_bytes directly should
--     use COALESCE(total_bytes, 0).
--   - UserKeys.DataLimit -> max_data_limit, UserKeys.ExpiredAt -> expires_at.
--   - UserKeys.GuiKey -> gui_key, and also covers what KeyNumber did
--     (dropped as redundant with GuiKey).
--   - UserKeys.ServerName (a free-text string) -> server_id (a proper FK
--     into `servers`). Import needs to resolve each old ServerName to a
--     servers.id.
--   - user_id references `users.id` (the app account), not
--     telegram_accounts.UserID — a Telegram-only user has no row here
--     unless/until they also get an app account.
-- ----------------------------------------------------------------------------
CREATE TABLE vpn_clients (
    id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id          BIGINT UNSIGNED NOT NULL,
    server_id        INT NOT NULL,
    protocol         ENUM('wireguard', 'outline') NOT NULL DEFAULT 'wireguard',

    -- WireGuard-specific — NULL on Outline rows
    public_key       VARCHAR(44)  DEFAULT NULL,   -- WireGuard public key, base64
    private_key      TEXT         DEFAULT NULL,   -- see security note below
    address          VARCHAR(45)  DEFAULT NULL,   -- this peer's tunnel IP, e.g. 10.8.0.5/32
    allowed_ips      VARCHAR(255) DEFAULT NULL,
    dns              VARCHAR(255) DEFAULT NULL,
    last_handshake   DATETIME     DEFAULT NULL,

    -- Outline-specific — NULL on WireGuard rows
    full_key         VARCHAR(512) DEFAULT NULL,   -- the ss:// access-key URI (was UserKeys.FullKey)
    gui_key          VARCHAR(100) DEFAULT NULL,   -- Outline access-key name/ID shown+used in the manager

    -- Shared by both protocols
    is_active        TINYINT(1) NOT NULL DEFAULT 1,
    is_expired       TINYINT(1) NOT NULL DEFAULT 0,
    is_suspended     TINYINT(1) NOT NULL DEFAULT 0,
    rx_bytes         BIGINT UNSIGNED DEFAULT NULL,  -- NULL until a usage poll reports it
    tx_bytes         BIGINT UNSIGNED DEFAULT NULL,  -- NULL until a usage poll reports it
    total_bytes      BIGINT UNSIGNED GENERATED ALWAYS AS (rx_bytes + tx_bytes) STORED,
    max_data_limit   BIGINT UNSIGNED DEFAULT NULL,  -- bytes (was UserKeys.DataLimit for Outline rows)
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at       DATETIME DEFAULT NULL,         -- (was UserKeys.ExpiredAt for Outline rows)

    PRIMARY KEY (id),
    UNIQUE KEY uq_vpn_clients_public_key (public_key),
    UNIQUE KEY uq_vpn_clients_full_key (full_key),
    INDEX idx_vpn_clients_user (user_id),
    INDEX idx_vpn_clients_server (server_id),
    INDEX idx_vpn_clients_protocol (protocol),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,

    -- Guardrail: a row must carry the fields its own protocol needs.
    CONSTRAINT chk_vpn_clients_protocol_fields CHECK (
        (protocol = 'wireguard' AND public_key IS NOT NULL AND address IS NOT NULL)
        OR
        (protocol = 'outline' AND full_key IS NOT NULL)
    )
);
-- Security note: storing a WireGuard peer's private_key, or an Outline
-- key's full access-key URI, server-side is convenient (the server can
-- hand it to the app again later) but means a database leak exposes live
-- credentials. The more conservative design has the device generate its
-- own WireGuard keypair (server only ever sees public_key) — Outline's
-- full_key, unlike a WireGuard private key, is inherently
-- server-generated and has to be stored somewhere to hand back to the
-- user, so that one column carries real risk if the database is ever
-- dumped; treat this table as sensitive and restrict who can read it.

-- ----------------------------------------------------------------------------
-- refresh_tokens — lets a login session be revoked (logout) instead of
-- only expiring on its own.
-- ----------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id      BIGINT UNSIGNED NOT NULL,
    token_hash   CHAR(64) NOT NULL,        -- sha256 hex digest of the raw token
    device_info  VARCHAR(255) DEFAULT NULL,
    issued_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME NOT NULL,
    revoked_at   DATETIME DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_refresh_tokens_hash (token_hash),
    INDEX idx_refresh_tokens_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- connection_logs — individual connect/disconnect events, so the app can
-- show "connected since" / per-session usage without recomputing from the
-- running totals in vpn_clients.
-- ----------------------------------------------------------------------------
CREATE TABLE connection_logs (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id            BIGINT UNSIGNED NOT NULL,
    client_id          BIGINT UNSIGNED NOT NULL,
    connected_at       DATETIME NOT NULL,
    disconnected_at    DATETIME DEFAULT NULL,
    bytes_used_session BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    INDEX idx_connection_logs_user (user_id),
    INDEX idx_connection_logs_client (client_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES vpn_clients(id) ON DELETE CASCADE
);

-- ============================================================================
-- Usage notes for the backend:
--
-- Register a user:
--   INSERT INTO users (username, password_hash, email, first_name, last_name)
--   VALUES (?, ?, ?, ?, ?);
--
-- Look up a user at login:
--   SELECT id, password_hash, is_active FROM users WHERE username = ?;
--
-- List servers the app should show:
--   SELECT id, alias, name, country, city, current_users, max_users, status
--   FROM servers
--   WHERE visible_to_app = 1 AND status = 'ACTIVE'
--   ORDER BY sort_order, country, city;
--
-- Get a user's total usage (across both protocols):
--   SELECT SUM(rx_bytes), SUM(tx_bytes), SUM(total_bytes)
--   FROM vpn_clients WHERE user_id = ?;
--
-- Issue a WireGuard peer:
--   INSERT INTO vpn_clients (user_id, server_id, protocol, public_key, address, allowed_ips)
--   VALUES (?, ?, 'wireguard', ?, ?, '0.0.0.0/0');
--
-- Issue an Outline key:
--   INSERT INTO vpn_clients (user_id, server_id, protocol, full_key, gui_key, max_data_limit)
--   VALUES (?, ?, 'outline', ?, ?, ?);
--
-- Bridging telegram_accounts and users (only if you ever need it):
-- if a Telegram-bot user also wants an app account, the clean way to link
-- them — now that both live in this same database — is a nullable, unique
-- column on `users`:
--   ALTER TABLE users ADD COLUMN telegram_user_id BIGINT UNSIGNED DEFAULT NULL,
--     ADD UNIQUE KEY uq_users_telegram_user_id (telegram_user_id),
--     ADD FOREIGN KEY (telegram_user_id) REFERENCES telegram_accounts(UserID) ON DELETE SET NULL;
-- Not created here since nothing in this request asked for that link yet.
-- ============================================================================
