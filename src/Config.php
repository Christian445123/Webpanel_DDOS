<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

final class Config
{
    private static ?array $data = null;

    public static function all(): array
    {
        if (self::$data === null) {
            Env::load(dirname(__DIR__) . '/.env');

            $appKey = Env::get('APP_KEY');
            if ($appKey === '') {
                throw new \RuntimeException(
                    '.env fehlt oder APP_KEY ist leer. Bitte .env.example nach .env kopieren und ausfüllen.'
                );
            }

            self::$data = [
                'db' => [
                    'host' => Env::get('DB_HOST', '127.0.0.1'),
                    'port' => Env::getInt('DB_PORT', 3306),
                    'database' => Env::get('DB_DATABASE'),
                    'username' => Env::get('DB_USERNAME'),
                    'password' => Env::get('DB_PASSWORD'),
                    'charset' => Env::get('DB_CHARSET', 'utf8mb4'),
                ],
                'app_key' => $appKey,
                'app_name' => Env::get('APP_NAME', 'VSRP DDoS Monitor'),
                'base_url' => Env::get('BASE_URL'),
                'timezone' => Env::get('APP_TIMEZONE', 'Europe/Vienna'),
                'mail' => [
                    'host' => Env::get('SMTP_HOST'),
                    'port' => Env::getInt('SMTP_PORT', 587),
                    'encryption' => Env::get('SMTP_ENCRYPTION', 'tls'), // tls|ssl|none
                    'username' => Env::get('SMTP_USERNAME'),
                    'password' => Env::get('SMTP_PASSWORD'),
                    'from_email' => Env::get('SMTP_FROM_EMAIL'),
                    'from_name' => Env::get('SMTP_FROM_NAME', 'VSRP DDoS Monitor'),
                    'alert_to' => Env::get('ALERT_EMAIL_TO'),
                ],
                'discord_webhook_url' => Env::get('DISCORD_WEBHOOK_URL'),
            ];

            date_default_timezone_set(self::$data['timezone']);
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
