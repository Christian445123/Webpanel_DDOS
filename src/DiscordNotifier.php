<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

final class DiscordNotifier
{
    public static function send(string $title, string $description, array $fields = [], int $color = 0xE74C3C): bool
    {
        $webhook = (string)Config::get('discord_webhook_url', '');
        if ($webhook === '') {
            return false;
        }

        $embed = [
            'title' => $title,
            'description' => $description,
            'color' => $color,
            'timestamp' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format(DATE_ATOM),
            'fields' => array_map(
                static fn($f) => ['name' => $f[0], 'value' => $f[1], 'inline' => $f[2] ?? false],
                $fields
            ),
        ];
        $payload = json_encode(['embeds' => [$embed]], JSON_UNESCAPED_UNICODE);

        $ch = curl_init($webhook);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
        ]);
        curl_exec($ch);
        $ok = curl_errno($ch) === 0;
        if (!$ok) {
            error_log('[VSRP-DDoS] Discord-Webhook-Fehler: ' . curl_error($ch));
        }
        curl_close($ch);
        return $ok;
    }
}
