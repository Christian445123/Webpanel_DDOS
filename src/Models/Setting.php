<?php

declare(strict_types=1);

namespace Vsrp\Ddos\Models;

use Vsrp\Ddos\Database;

/**
 * Einfacher Key-Value-Einstellungsspeicher (Tabelle `settings`), mit Prozess-Cache.
 */
final class Setting
{
    private static ?array $cache = null;

    public static function all(): array
    {
        if (self::$cache === null) {
            $rows = Database::connection()->query('SELECT setting_key, setting_value FROM settings')->fetchAll();
            self::$cache = [];
            foreach ($rows as $row) {
                self::$cache[$row['setting_key']] = $row['setting_value'];
            }
        }
        return self::$cache;
    }

    /**
     * Erzwingt beim nächsten Zugriff ein Neuladen aus der Datenbank. Wichtig für lang laufende
     * Prozesse (Collector-Dienst), damit im Web-UI geänderte Einstellungen ohne Neustart wirken.
     */
    public static function refresh(): void
    {
        self::$cache = null;
    }

    public static function get(string $key, string $default = ''): string
    {
        $all = self::all();
        return array_key_exists($key, $all) && $all[$key] !== null ? (string)$all[$key] : $default;
    }

    public static function getInt(string $key, int $default = 0): int
    {
        $value = self::get($key, (string)$default);
        return $value === '' ? $default : (int)$value;
    }

    public static function getFloat(string $key, float $default = 0.0): float
    {
        $value = self::get($key, (string)$default);
        return $value === '' ? $default : (float)$value;
    }

    public static function set(string $key, string $value): void
    {
        $stmt = Database::connection()->prepare(
            'INSERT INTO settings (setting_key, setting_value) VALUES (:k, :v)
             ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)'
        );
        $stmt->execute(['k' => $key, 'v' => $value]);
        self::$cache = null;
    }

    public static function setMany(array $values): void
    {
        $db = Database::connection();
        $db->beginTransaction();
        try {
            $stmt = $db->prepare(
                'INSERT INTO settings (setting_key, setting_value) VALUES (:k, :v)
                 ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)'
            );
            foreach ($values as $key => $value) {
                $stmt->execute(['k' => $key, 'v' => (string)$value]);
            }
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollBack();
            throw $e;
        }
        self::$cache = null;
    }
}
