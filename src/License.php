<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

/**
 * Lizenzschlüssel für den C#-Admin-Client (Format VDOS-XXXX-XXXX-XXXX-XXXX).
 * Gespeichert wird nur der SHA-256-Hash; der Klartext-Schlüssel wird bei der Erstellung einmalig angezeigt.
 */
final class License
{
    public static function newKey(): string
    {
        $hex = strtoupper(bin2hex(random_bytes(8)));
        return 'VDOS-' . implode('-', str_split($hex, 4));
    }

    public static function normalize(string $key): string
    {
        return strtoupper(trim($key));
    }

    public static function hash(string $key): string
    {
        return hash('sha256', self::normalize($key));
    }

    /** @return array{id:int,label:string,expires_at:?string}|null */
    public static function validate(string $key): ?array
    {
        if (trim($key) === '') {
            return null;
        }
        $stmt = Database::connection()->prepare(
            'SELECT id, label, expires_at FROM licenses
             WHERE key_hash = :h AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at >= CURDATE()) LIMIT 1'
        );
        $stmt->execute(['h' => self::hash($key)]);
        $row = $stmt->fetch();
        if (!$row) {
            return null;
        }
        Database::connection()->prepare('UPDATE licenses SET last_used_at = NOW(), last_ip = :ip WHERE id = :id')
            ->execute(['ip' => $_SERVER['REMOTE_ADDR'] ?? null, 'id' => $row['id']]);
        return ['id' => (int)$row['id'], 'label' => $row['label'], 'expires_at' => $row['expires_at']];
    }
}
