<?php
/** @var string $pageTitle */
/** @var string $activeNav */
use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Config;
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars($pageTitle ?? 'VSRP DDoS Monitor') ?></title>
    <link rel="stylesheet" href="/assets/css/app.css">
</head>
<body>
<?php if (Auth::check()): ?>
<div class="topbar">
    <div class="brand">🛡️ <?= htmlspecialchars(Config::get('app_name', 'VSRP DDoS Monitor')) ?></div>
    <nav>
        <a href="/dashboard.php" class="<?= ($activeNav ?? '') === 'dashboard' ? 'active' : '' ?>">Dashboard</a>
        <a href="/incidents.php" class="<?= ($activeNav ?? '') === 'incidents' ? 'active' : '' ?>">Vorfälle</a>
        <a href="/api_keys.php" class="<?= ($activeNav ?? '') === 'api_keys' ? 'active' : '' ?>">API-Zugang</a>
        <a href="/servers.php" class="<?= ($activeNav ?? '') === 'servers' ? 'active' : '' ?>">Server</a>
        <a href="/licenses.php" class="<?= ($activeNav ?? '') === 'licenses' ? 'active' : '' ?>">Lizenzen</a>
        <a href="/settings.php" class="<?= ($activeNav ?? '') === 'settings' ? 'active' : '' ?>">Einstellungen</a>
        <span class="muted"><?= htmlspecialchars(Auth::username()) ?></span>
        &nbsp;·&nbsp;
        <a href="/logout.php">Abmelden</a>
    </nav>
</div>
<?php endif; ?>
<div class="container">
