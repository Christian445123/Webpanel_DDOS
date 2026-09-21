<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

/**
 * Sehr schlanker SMTP-Client ohne Abhängigkeiten (kein Composer/PHPMailer nötig).
 * Unterstützt SSL (Port 465), STARTTLS (Port 587) und Klartext, sowie AUTH LOGIN.
 */
final class Mail
{
    public static function send(string $toEmail, string $subject, string $body): bool
    {
        $host = Models\Setting::get('smtp_host');
        $port = Models\Setting::getInt('smtp_port', 587);
        $encryption = Models\Setting::get('smtp_encryption', 'tls'); // tls|ssl|none
        $username = Models\Setting::get('smtp_username');
        $password = Models\Setting::get('smtp_password');
        $fromEmail = Models\Setting::get('smtp_from_email');
        $fromName = Models\Setting::get('smtp_from_name', 'VSRP DDoS Monitor');

        if ($host === '' || $fromEmail === '' || $toEmail === '') {
            return false;
        }

        $transport = $encryption === 'ssl' ? 'ssl://' . $host : $host;
        $sock = @stream_socket_client($transport . ':' . $port, $errno, $errstr, 10);
        if (!$sock) {
            error_log("[VSRP-DDoS] SMTP-Verbindung fehlgeschlagen: $errstr ($errno)");
            return false;
        }
        stream_set_timeout($sock, 15);

        try {
            self::expect($sock, '220');
            self::command($sock, 'EHLO ' . self::ehloName(), '250');

            if ($encryption === 'tls') {
                self::command($sock, 'STARTTLS', '220');
                if (!stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new \RuntimeException('STARTTLS fehlgeschlagen.');
                }
                self::command($sock, 'EHLO ' . self::ehloName(), '250');
            }

            if ($username !== '') {
                self::command($sock, 'AUTH LOGIN', '334');
                self::command($sock, base64_encode($username), '334');
                self::command($sock, base64_encode($password), '235');
            }

            self::command($sock, 'MAIL FROM:<' . $fromEmail . '>', '250');
            foreach (self::splitRecipients($toEmail) as $recipient) {
                self::command($sock, 'RCPT TO:<' . $recipient . '>', '250');
            }
            self::command($sock, 'DATA', '354');

            $headers = [
                'From: ' . self::encodeHeader($fromName) . ' <' . $fromEmail . '>',
                'To: <' . $toEmail . '>',
                'Subject: ' . self::encodeHeader($subject),
                'MIME-Version: 1.0',
                'Content-Type: text/plain; charset=UTF-8',
                'Content-Transfer-Encoding: 8bit',
                'Date: ' . date('r'),
            ];
            $data = implode("\r\n", $headers) . "\r\n\r\n" . str_replace("\n.", "\n..", $body) . "\r\n.";
            self::command($sock, $data, '250');
            self::command($sock, 'QUIT', '221');
            return true;
        } catch (\Throwable $e) {
            error_log('[VSRP-DDoS] SMTP-Fehler: ' . $e->getMessage());
            return false;
        } finally {
            fclose($sock);
        }
    }

    private static function splitRecipients(string $to): array
    {
        $parts = array_map('trim', explode(',', $to));
        return array_filter($parts, static fn($p) => $p !== '');
    }

    private static function ehloName(): string
    {
        return gethostname() ?: 'localhost';
    }

    private static function encodeHeader(string $value): string
    {
        return preg_match('/[^\x20-\x7E]/', $value) ? '=?UTF-8?B?' . base64_encode($value) . '?=' : $value;
    }

    private static function expect($sock, string $code): void
    {
        $line = '';
        do {
            $line = fgets($sock, 515);
            if ($line === false) {
                throw new \RuntimeException('SMTP-Verbindung unterbrochen.');
            }
        } while (isset($line[3]) && $line[3] === '-');
        if (substr($line, 0, 3) !== $code) {
            throw new \RuntimeException('Unerwartete SMTP-Antwort: ' . trim($line));
        }
    }

    private static function command($sock, string $command, string $expectCode): void
    {
        fwrite($sock, $command . "\r\n");
        self::expect($sock, $expectCode);
    }
}
