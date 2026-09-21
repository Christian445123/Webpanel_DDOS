<?php

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Config;

if (Auth::check()) {
    header('Location: /dashboard.php');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Auth::checkCsrf()) {
        $error = 'Sitzung abgelaufen, bitte erneut versuchen.';
    } else {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        if (Auth::attempt($username, $password)) {
            header('Location: /dashboard.php');
            exit;
        }
        $error = 'Benutzername oder Passwort ist falsch.';
    }
}

$pageTitle = 'Anmelden – ' . Config::get('app_name', 'VSRP DDoS Monitor');
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars($pageTitle) ?></title>
    <link rel="icon" type="image/x-icon" href="/assets/favicon.ico">
    <link rel="apple-touch-icon" href="/assets/icon-192.png">
    <link rel="stylesheet" href="/assets/css/app.css">
</head>
<body>
<div class="login-wrap">
    <div class="login-box">
        <h1><img src="/assets/logo.png" alt="" width="40" height="40" style="vertical-align:middle;margin-right:10px;border-radius:8px"><?= htmlspecialchars(Config::get('app_name', 'VSRP DDoS Monitor')) ?></h1>
        <?php if ($error !== ''): ?>
            <div class="alert error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
            <div class="form-row">
                <label for="username">Benutzername</label>
                <input type="text" id="username" name="username" autofocus required>
            </div>
            <div class="form-row">
                <label for="password">Passwort</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn primary" style="width:100%">Anmelden</button>
        </form>
    </div>
</div>
</body>
</html>
