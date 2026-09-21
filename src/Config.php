<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

final class Config
{
    private static ?array $data = null;

    public static function all(): array
    {
        if (self::$data === null) {
            $path = dirname(__DIR__) . '/config/config.php';
            if (!is_file($path)) {
                throw new \RuntimeException(
                    'config/config.php fehlt. Bitte config/config.example.php kopieren, ausfüllen und als config/config.php speichern.'
                );
            }
            self::$data = require $path;
            date_default_timezone_set(self::$data['timezone'] ?? 'UTC');
        }
        return self::$data;
    }

    public static function get(string $dotKey, mixed $default = null): mixed
    {
        $value = self::all();
        foreach (explode('.', $dotKey) as $part) {
            if (!is_array($value) || !array_key_exists($part, $value)) {
                return $default;
            }
            $value = $value[$part];
        }
        return $value;
    }
}
