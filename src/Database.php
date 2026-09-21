<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

use PDO;
use PDOException;

final class Database
{
    private static ?PDO $pdo = null;

    public static function connection(): PDO
    {
        if (self::$pdo === null) {
            $cfg = Config::get('db');
            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                $cfg['host'],
                $cfg['port'] ?? 3306,
                $cfg['database'],
                $cfg['charset'] ?? 'utf8mb4'
            );
            try {
                self::$pdo = new PDO($dsn, $cfg['username'], $cfg['password'], [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]);
            } catch (PDOException $e) {
                throw new \RuntimeException('Datenbankverbindung fehlgeschlagen: ' . $e->getMessage(), 0, $e);
            }
            Migrator::run(self::$pdo);
        }
        return self::$pdo;
    }
}
