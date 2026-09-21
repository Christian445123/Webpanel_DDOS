<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

/**
 * Prüft API-Schlüssel für die REST-API (genutzt vom C#-Admin-Client).
 * Schlüssel werden nur als SHA-256-Hash in der Datenbank gespeichert (Tabelle api_keys).
 */
final class ApiAuth
{
    public static function newKey(): string
    {
        return 'vddos_' . bin2hex(random_bytes(24));
    }

    public static function hash(string $key): string
    {
        return hash('sha256', $key);
    }

    /** @return array{id:int,label:string}|null */
    public static function authenticate(): ?array
    {
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $key = '';
        if (preg_match('/^Bearer\s+(.+)$/i', $header, $m)) {
            $key = trim($m[1]);
        } elseif (!empty($_SERVER['HTTP_X_API_KEY'])) {
            $key = trim($_SERVER['HTTP_X_API_KEY']);
        }
        if ($key === '') {
            return null;
        }

        $stmt = Database::connection()->prepare(
            'SELECT id, label FROM api_keys WHERE token_hash = :h AND revoked_at IS NULL LIMIT 1'
        );
        $stmt->execute(['h' => self::hash($key)]);
        $row = $stmt->fetch();
        if (!$row) {
            return null;
        }

        $upd = Database::connection()->prepare('UPDATE api_keys SET last_used_at = NOW() WHERE id = :id');
        $upd->execute(['id' => $row['id']]);

        return ['id' => (int)$row['id'], 'label' => $row['label']];
    }
}
