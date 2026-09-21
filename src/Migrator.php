<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

use PDO;

/**
 * Ergänzt bei bestehenden Installationen neu hinzugekommene Tabellen/Spalten selbstständig
 * (schema.sql legt nur bei Neuinstallation alles an). Läuft je Prozess einmal, ändert nie vorhandene Daten.
 */
final class Migrator
{
    public static function run(PDO $db): void
    {
        try {
            $db->exec(
                'CREATE TABLE IF NOT EXISTS servers (
                    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    token_hash CHAR(64) NOT NULL UNIQUE,
                    token_hint CHAR(4) NOT NULL,
                    hostname VARCHAR(255) NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    revoked_at DATETIME NULL,
                    last_seen_at DATETIME NULL,
                    last_ip VARCHAR(45) NULL,
                    state_json TEXT NULL,
                    offline_notified TINYINT(1) NOT NULL DEFAULT 0
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
            );
            foreach (['samples', 'incidents'] as $table) {
                $has = $db->query("SHOW COLUMNS FROM {$table} LIKE 'server_id'")->fetch();
                if (!$has) {
                    $db->exec("ALTER TABLE {$table} ADD COLUMN server_id INT UNSIGNED NULL");
                    $db->exec("ALTER TABLE {$table} ADD INDEX idx_{$table}_server (server_id)");
                }
            }
        } catch (\Throwable $e) {
            error_log('[VSRP-DDoS] Migration fehlgeschlagen: ' . $e->getMessage());
        }
    }
}
