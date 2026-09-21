-- VSRP DDoS Monitor - Datenbankschema (MySQL/MariaDB)
-- Einspielen: mysql -u <user> -p <datenbank> < db/schema.sql

CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS api_keys (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    label VARCHAR(100) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by INT UNSIGNED NULL,
    last_used_at DATETIME NULL,
    revoked_at DATETIME NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Konfiguration als einfacher Key-Value-Speicher (nur Erkennungs-Schwellwerte), im Web-UI unter
-- "Einstellungen" editierbar. Zugangsdaten (Datenbank, SMTP, Discord-Webhook) liegen NICHT hier,
-- sondern in der .env-Datei (siehe .env.example).
CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Zeitreihe der Messungen (vom Collector-Dienst alle paar Sekunden geschrieben)
CREATE TABLE IF NOT EXISTS samples (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ts DATETIME NOT NULL,
    mbit_in DECIMAL(12,3) NOT NULL DEFAULT 0,
    pps_in INT UNSIGNED NOT NULL DEFAULT 0,
    mbit_out DECIMAL(12,3) NOT NULL DEFAULT 0,
    pps_out INT UNSIGNED NOT NULL DEFAULT 0,
    total_conn INT UNSIGNED NOT NULL DEFAULT 0,
    syn_recv INT UNSIGNED NOT NULL DEFAULT 0,
    incident_id INT UNSIGNED NULL,
    INDEX idx_samples_ts (ts),
    INDEX idx_samples_incident (incident_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS incidents (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    started_at DATETIME NOT NULL,
    resolved_at DATETIME NULL,
    status ENUM('active','resolved') NOT NULL DEFAULT 'active',
    peak_mbit_in DECIMAL(12,3) NOT NULL DEFAULT 0,
    peak_pps_in INT UNSIGNED NOT NULL DEFAULT 0,
    peak_total_conn INT UNSIGNED NOT NULL DEFAULT 0,
    peak_syn_recv INT UNSIGNED NOT NULL DEFAULT 0,
    trigger_reason VARCHAR(255) NOT NULL DEFAULT '',
    notified_email TINYINT(1) NOT NULL DEFAULT 0,
    notified_discord TINYINT(1) NOT NULL DEFAULT 0,
    resolved_notified TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_incidents_status (status),
    INDEX idx_incidents_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Auffällige externe IPs je Vorfall, inkl. vorgeschlagenem (nicht automatisch ausgeführtem) Blockierbefehl
CREATE TABLE IF NOT EXISTS suspects (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id INT UNSIGNED NOT NULL,
    ip VARCHAR(45) NOT NULL,
    conn_count INT UNSIGNED NOT NULL DEFAULT 0,
    syn_recv_count INT UNSIGNED NOT NULL DEFAULT 0,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    suggested_cmd_nft TEXT NULL,
    suggested_cmd_iptables TEXT NULL,
    status ENUM('pending','manual_blocked','ignored') NOT NULL DEFAULT 'pending',
    status_updated_by VARCHAR(100) NULL,
    status_updated_at DATETIME NULL,
    UNIQUE KEY uniq_incident_ip (incident_id, ip),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO settings (setting_key, setting_value) VALUES
    ('mbit_threshold', '800'),
    ('pps_threshold', '150000'),
    ('total_conn_threshold', '2500'),
    ('syn_recv_threshold', '300'),
    ('per_ip_conn_threshold', '80'),
    ('sample_interval_seconds', '10'),
    ('consecutive_to_trigger', '3'),
    ('consecutive_to_resolve', '6'),
    ('monitor_interface', 'eth0'),
    ('samples_retention_days', '14')
ON DUPLICATE KEY UPDATE setting_key = setting_key;

-- Lizenzschluessel fuer den C#-Admin-Client (nur der SHA-256-Hash wird gespeichert)
CREATE TABLE IF NOT EXISTS licenses (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    label VARCHAR(100) NOT NULL,
    key_hash CHAR(64) NOT NULL UNIQUE,
    key_hint CHAR(4) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATE NULL,
    revoked_at DATETIME NULL,
    last_used_at DATETIME NULL,
    last_ip VARCHAR(45) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
