<?php

declare(strict_types=1);

require dirname(__DIR__) . '/autoload.php';

use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Database;
use Vsrp\Ddos\Mail;
use Vsrp\Ddos\Models\Setting;

Auth::requireLogin();

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && Auth::checkCsrf()) {
    $form = (string)($_POST['form'] ?? '');

    if ($form === 'thresholds') {
        Setting::setMany([
            'mbit_threshold' => (float)($_POST['mbit_threshold'] ?? 800),
            'pps_threshold' => (int)($_POST['pps_threshold'] ?? 150000),
            'total_conn_threshold' => (int)($_POST['total_conn_threshold'] ?? 2500),
            'syn_recv_threshold' => (int)($_POST['syn_recv_threshold'] ?? 300),
            'per_ip_conn_threshold' => (int)($_POST['per_ip_conn_threshold'] ?? 80),
            'sample_interval_seconds' => (int)($_POST['sample_interval_seconds'] ?? 10),
            'consecutive_to_trigger' => (int)($_POST['consecutive_to_trigger'] ?? 3),
            'consecutive_to_resolve' => (int)($_POST['consecutive_to_resolve'] ?? 6),
            'monitor_interface' => trim((string)($_POST['monitor_interface'] ?? 'eth0')),
            'samples_retention_days' => (int)($_POST['samples_retention_days'] ?? 14),
        ]);
        $message = 'Schwellwerte gespeichert. Der Collector-Dienst übernimmt sie beim nächsten Messzyklus.';
    } elseif ($form === 'notifications') {
        Setting::setMany([
            'smtp_host' => trim((string)($_POST['smtp_host'] ?? '')),
            'smtp_port' => (int)($_POST['smtp_port'] ?? 587),
            'smtp_encryption' => (string)($_POST['smtp_encryption'] ?? 'tls'),
            'smtp_username' => trim((string)($_POST['smtp_username'] ?? '')),
            'smtp_password' => (string)($_POST['smtp_password'] ?? ''),
            'smtp_from_email' => trim((string)($_POST['smtp_from_email'] ?? '')),
            'smtp_from_name' => trim((string)($_POST['smtp_from_name'] ?? '')),
            'alert_email_to' => trim((string)($_POST['alert_email_to'] ?? '')),
            'discord_webhook_url' => trim((string)($_POST['discord_webhook_url'] ?? '')),
        ]);
        $message = 'Benachrichtigungseinstellungen gespeichert.';
    } elseif ($form === 'test_email') {
        $to = Setting::get('alert_email_to');
        if ($to === '') {
            $error = 'Bitte zuerst eine Alarm-E-Mail-Adresse eintragen und speichern.';
        } elseif (Mail::send($to, 'Testmail – VSRP DDoS Monitor', "Das ist eine Testnachricht.\nWenn diese ankommt, sind die SMTP-Einstellungen korrekt.")) {
            $message = 'Test-E-Mail wurde verschickt (an ' . $to . ').';
        } else {
            $error = 'Test-E-Mail konnte nicht verschickt werden. Bitte SMTP-Einstellungen und PHP-Fehlerlog prüfen.';
        }
    } elseif ($form === 'password') {
        $current = (string)($_POST['current_password'] ?? '');
        $new = (string)($_POST['new_password'] ?? '');
        $stmt = Database::connection()->prepare('SELECT id, password_hash FROM users WHERE username = :u');
        $stmt->execute(['u' => Auth::username()]);
        $user = $stmt->fetch();
        if (!$user || !password_verify($current, $user['password_hash'])) {
            $error = 'Aktuelles Passwort ist falsch.';
        } elseif (strlen($new) < 10) {
            $error = 'Neues Passwort muss mindestens 10 Zeichen haben.';
        } else {
            Database::connection()->prepare('UPDATE users SET password_hash = :h WHERE id = :id')
                ->execute(['h' => password_hash($new, PASSWORD_DEFAULT), 'id' => $user['id']]);
            $message = 'Passwort geändert.';
        }
    }
}

$pageTitle = 'Einstellungen';
$activeNav = 'settings';
require __DIR__ . '/_layout_top.php';
?>

<?php if ($message !== ''): ?><div class="alert success"><?= htmlspecialchars($message) ?></div><?php endif; ?>
<?php if ($error !== ''): ?><div class="alert error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

<div class="panel">
    <h2>Schwellwerte für die Erkennung</h2>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
        <input type="hidden" name="form" value="thresholds">
        <div class="grid-2">
            <div class="form-row">
                <label>Bandbreite-Schwelle (MBit/s eingehend)</label>
                <input type="number" step="0.1" name="mbit_threshold" value="<?= htmlspecialchars(Setting::get('mbit_threshold', '800')) ?>">
            </div>
            <div class="form-row">
                <label>Pakete/s-Schwelle</label>
                <input type="number" name="pps_threshold" value="<?= htmlspecialchars(Setting::get('pps_threshold', '150000')) ?>">
            </div>
            <div class="form-row">
                <label>Verbindungen gesamt – Schwelle</label>
                <input type="number" name="total_conn_threshold" value="<?= htmlspecialchars(Setting::get('total_conn_threshold', '2500')) ?>">
            </div>
            <div class="form-row">
                <label>SYN-RECV – Schwelle</label>
                <input type="number" name="syn_recv_threshold" value="<?= htmlspecialchars(Setting::get('syn_recv_threshold', '300')) ?>">
            </div>
            <div class="form-row">
                <label>Verbindungen je Einzel-IP – Schwelle</label>
                <input type="number" name="per_ip_conn_threshold" value="<?= htmlspecialchars(Setting::get('per_ip_conn_threshold', '80')) ?>">
            </div>
            <div class="form-row">
                <label>Messintervall (Sekunden)</label>
                <input type="number" name="sample_interval_seconds" value="<?= htmlspecialchars(Setting::get('sample_interval_seconds', '10')) ?>">
            </div>
            <div class="form-row">
                <label>Aufeinanderfolgende Messungen bis Alarm</label>
                <input type="number" name="consecutive_to_trigger" value="<?= htmlspecialchars(Setting::get('consecutive_to_trigger', '3')) ?>">
            </div>
            <div class="form-row">
                <label>Aufeinanderfolgende Messungen bis Entwarnung</label>
                <input type="number" name="consecutive_to_resolve" value="<?= htmlspecialchars(Setting::get('consecutive_to_resolve', '6')) ?>">
            </div>
            <div class="form-row">
                <label>Netzwerkschnittstelle (z. B. eth0)</label>
                <input type="text" name="monitor_interface" value="<?= htmlspecialchars(Setting::get('monitor_interface', 'eth0')) ?>">
            </div>
            <div class="form-row">
                <label>Messwerte aufbewahren (Tage, außerhalb von Vorfällen)</label>
                <input type="number" name="samples_retention_days" value="<?= htmlspecialchars(Setting::get('samples_retention_days', '14')) ?>">
            </div>
        </div>
        <button type="submit" class="btn primary">Speichern</button>
    </form>
</div>

<div class="panel">
    <h2>Benachrichtigungen</h2>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
        <input type="hidden" name="form" value="notifications">
        <h3 style="font-size:13px;color:var(--muted)">E-Mail (SMTP)</h3>
        <div class="grid-2">
            <div class="form-row"><label>SMTP-Host</label><input type="text" name="smtp_host" value="<?= htmlspecialchars(Setting::get('smtp_host')) ?>"></div>
            <div class="form-row"><label>Port</label><input type="number" name="smtp_port" value="<?= htmlspecialchars(Setting::get('smtp_port', '587')) ?>"></div>
            <div class="form-row">
                <label>Verschlüsselung</label>
                <select name="smtp_encryption">
                    <?php foreach (['tls' => 'STARTTLS (587)', 'ssl' => 'SSL/TLS (465)', 'none' => 'Keine'] as $val => $label): ?>
                        <option value="<?= $val ?>" <?= Setting::get('smtp_encryption', 'tls') === $val ? 'selected' : '' ?>><?= $label ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-row"><label>Benutzername</label><input type="text" name="smtp_username" value="<?= htmlspecialchars(Setting::get('smtp_username')) ?>"></div>
            <div class="form-row"><label>Passwort</label><input type="password" name="smtp_password" value="<?= htmlspecialchars(Setting::get('smtp_password')) ?>"></div>
            <div class="form-row"><label>Absender-E-Mail</label><input type="email" name="smtp_from_email" value="<?= htmlspecialchars(Setting::get('smtp_from_email')) ?>"></div>
            <div class="form-row"><label>Absendername</label><input type="text" name="smtp_from_name" value="<?= htmlspecialchars(Setting::get('smtp_from_name', 'VSRP DDoS Monitor')) ?>"></div>
            <div class="form-row"><label>Alarm-E-Mail an (mehrere mit Komma trennen)</label><input type="text" name="alert_email_to" value="<?= htmlspecialchars(Setting::get('alert_email_to')) ?>"></div>
        </div>
        <h3 style="font-size:13px;color:var(--muted)">Discord</h3>
        <div class="form-row">
            <label>Discord-Webhook-URL</label>
            <input type="text" name="discord_webhook_url" value="<?= htmlspecialchars(Setting::get('discord_webhook_url')) ?>">
        </div>
        <button type="submit" class="btn primary">Speichern</button>
    </form>
    <form method="post" style="margin-top:10px">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
        <input type="hidden" name="form" value="test_email">
        <button type="submit" class="btn">Test-E-Mail senden</button>
    </form>
</div>

<div class="panel">
    <h2>Eigenes Passwort ändern</h2>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
        <input type="hidden" name="form" value="password">
        <div class="grid-2">
            <div class="form-row"><label>Aktuelles Passwort</label><input type="password" name="current_password" required></div>
            <div class="form-row"><label>Neues Passwort (mind. 10 Zeichen)</label><input type="password" name="new_password" required minlength="10"></div>
        </div>
        <button type="submit" class="btn primary">Passwort ändern</button>
    </form>
</div>

<?php require __DIR__ . '/_layout_bottom.php'; ?>
