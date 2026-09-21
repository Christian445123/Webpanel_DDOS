<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

final class Auth
{
    public static function start(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            session_start();
        }
    }

    public static function attempt(string $username, string $password): bool
    {
        $stmt = Database::connection()->prepare('SELECT id, password_hash FROM users WHERE username = :u LIMIT 1');
        $stmt->execute(['u' => $username]);
        $user = $stmt->fetch();
        if (!$user || !password_verify($password, $user['password_hash'])) {
            usleep(300000); // Zeitangleich, um Kontoerkennung per Timing zu erschweren
            return false;
        }
        self::start();
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int)$user['id'];
        $_SESSION['username'] = $username;

        $upd = Database::connection()->prepare('UPDATE users SET last_login_at = NOW() WHERE id = :id');
        $upd->execute(['id' => $user['id']]);
        return true;
    }

    public static function check(): bool
    {
        self::start();
        return isset($_SESSION['user_id']);
    }

    public static function requireLogin(): void
    {
        if (!self::check()) {
            header('Location: /login.php');
            exit;
        }
    }

    public static function username(): string
    {
        self::start();
        return $_SESSION['username'] ?? '';
    }

    public static function logout(): void
    {
        self::start();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
    }

    public static function csrfToken(): string
    {
        self::start();
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf'];
    }

    public static function checkCsrf(): bool
    {
        self::start();
        $token = $_POST['csrf'] ?? '';
        return is_string($token) && hash_equals($_SESSION['csrf'] ?? '', $token);
    }
}
