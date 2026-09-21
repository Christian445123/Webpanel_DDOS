<?php

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Vsrp\Ddos\ApiAuth;
use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Config;
use Vsrp\Ddos\Database;

Auth::requireLogin();

$db = Database::connection();
$newKey = '';
$newName = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && Auth::checkCsrf()) {
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'create') {
        $newName = substr(trim((string)($_POST['name'] ?? '')) ?: 'Server', 0, 100);
        $newKey = ApiAuth::newServerKey();
        $db->prepare('INSERT INTO servers (name, token_hash, token_hint) VALUES (:n, :h, :hint)')
            ->execute(['n' => $newName, 'h' => ApiAuth::hash($newKey), 'hint' => substr($newKey, -4)]);
    } elseif ($action === 'revoke') {
        $db->prepare('UPDATE servers SET revoked_at = NOW() WHERE id = :id')->execute(['id' => (int)($_POST['id'] ?? 0)]);
    }
}

$servers = $db->query(
    "SELECT s.*, (SELECT COUNT(*) FROM incidents i WHERE i.server_id = s.id AND i.status = 'active') AS active_incidents
     FROM servers s ORDER BY s.id DESC"
)->fetchAll();

$baseUrl = rtrim((string)Config::get('base_url', ''), '/');
$pageTitle = 'Server';
$activeNav = 'servers';
require __DIR__ . '/_layout_top.php';
?>

<?php if ($newKey !== ''): ?>
    <div class="alert warning">
        <strong>Server „<?= htmlspecialchars($newName) ?>“ angelegt. Der Schlüssel wird nur jetzt angezeigt.</strong><br>
        Auf dem Linux-Server als root ausführen:<br>
        <span class="mono" id="install-cmd">curl -fsSL <?= htmlspecialchars($baseUrl) ?>/agent/install.sh | sudo bash -s -- <?= htmlspecialchars($newKey) ?></span>
        <button type="button" class="btn small" onclick="navigator.clipboard.writeText(document.getElementById('install-cmd').innerText)">Kopieren</button>
    </div>
<?php endif; ?>

<div class="panel">
    <h2>Neuen Server hinzufügen</h2>
    <p class="muted">
        Auf jedem zu überwachenden Linux-Server läuft ein kleiner Agent, der alle paar Sekunden Netzwerkwerte hierher meldet.
        Der Installer ist für alle Server gleich, nur der Schlüssel unterscheidet sich. Blockiert wird nichts automatisch.
    </p>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
        <input type="hidden" name="action" value="create">
        <div class="form-row" style="max-width:320px">
            <label>Name des Servers</label>
            <input type="text" name="name" placeholder="z. B. FiveM-Server 1" required>
        </div>
        <button type="submit" class="btn primary">Server anlegen</button>
    </form>
</div>

<div class="panel">
    <h2>Überwachte Server</h2>
    <?php if (!$servers): ?>
        <p class="muted">Noch keine Server angelegt.</p>
    <?php else: ?>
        <table>
            <thead><tr><th>Name</th><th>Host</th><th>Schlüssel</th><th>Zuletzt gemeldet</th><th>Status</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($servers as $s): ?>
                <?php
                $seen = $s['last_seen_at'] ? strtotime($s['last_seen_at']) : null;
                $online = $seen !== null && time() - $seen < 90;
                ?>
                <tr>
                    <td><?= htmlspecialchars($s['name']) ?></td>
                    <td class="mono"><?= htmlspecialchars((string)($s['hostname'] ?: '–')) ?><br><span class="muted"><?= htmlspecialchars((string)($s['last_ip'] ?? '')) ?></span></td>
                    <td class="mono">vsrv_…<?= htmlspecialchars($s['token_hint']) ?></td>
                    <td><?= htmlspecialchars($s['last_seen_at'] ?? 'noch nie') ?></td>
                    <td>
                        <?php if ($s['revoked_at']): ?><span class="badge ignored">widerrufen</span>
                        <?php elseif ((int)$s['active_incidents'] > 0): ?><span class="badge active">DDoS-Verdacht</span>
                        <?php elseif ($online): ?><span class="badge resolved">online</span>
                        <?php elseif ($seen === null): ?><span class="badge pending">wartet auf Agent</span>
                        <?php else: ?><span class="badge pending">keine Meldung</span><?php endif; ?>
                    </td>
                    <td>
                        <?php if (!$s['revoked_at']): ?>
                            <form method="post" style="display:inline" onsubmit="return confirm('Server-Schlüssel wirklich widerrufen? Der Agent wird dann abgelehnt.');">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
                                <input type="hidden" name="action" value="revoke">
                                <input type="hidden" name="id" value="<?= (int)$s['id'] ?>">
                                <button type="submit" class="btn small">Widerrufen</button>
                            </form>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/_layout_bottom.php'; ?>
