<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

/**
 * Sehr schlanker .env-Loader (kein Composer/vlucas-vlucas nötig).
 * Format: KEY=VALUE je Zeile, "#" leitet Kommentare ein, Werte optional in " oder ' gequotet.
 */
final class Env
{
    private static bool $loaded = false;

    public static function load(string $path): void
    {
        if (self::$loaded) {
            return;
        }
        self::$loaded = true;

        if (!is_file($path)) {
            return;
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
                continue;
            }
            [$key, $value] = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            if ($key === '') {
                continue;
            }
            if (strlen($value) >= 2 && ($value[0] === '"' || $value[0] === "'") && $value[-1] === $value[0]) {
                $value = substr($value, 1, -1);
            }

            // Bereits gesetzte echte Umgebungsvariablen (z. B. aus systemd `Environment=`) haben Vorrang
            if (getenv($key) === false) {
                putenv($key . '=' . $value);
                $_ENV[$key] = $value;
            }
        }
    }

    public static function get(string $key, string $default = ''): string
    {
        $value = $_ENV[$key] ?? getenv($key);
        return $value === false || $value === null ? $default : (string)$value;
    }

    public static function getInt(string $key, int $default = 0): int
    {
        $value = self::get($key, '');
        return $value === '' ? $default : (int)$value;
    }
}
