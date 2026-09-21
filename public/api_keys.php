<?php

declare(strict_types=1);

require dirname(__DIR__) . '/autoload.php';

use Vsrp\Ddos\ApiAuth;
use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Database;

Auth::requireLogin();

$newKey = '';
$db = Database::connection();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && Auth::checkCsrf()) {
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'create') {
        $label = trim((string)($_POST['label'] ?? '')) ?: 'C#-Admin-Client';
        $newKey = ApiAuth::newKey();
        $stmt = $db->prepare(
            'INSERT INTO api_keys (label, token_hash, created_by) VALUES (:l, :h, :u)'
        );
        $stmt->execute(['l' => $label, 'h' => ApiAuth::hash($newKey), 'u' => $_SESSION['user_id']]);
    } elseif ($action === 'revoke') {
        $id = (int)($_POST['id'] ?? 0);
        $db->prepare('UPDATE api_keys SET revoked_at = NOW() WHERE id = :id')->execute(['id' => $id]);
    }
}

$keys = $db->query('SELECT * FROM api_keys ORDER BY id DESC')->fetchAll();

$pageTitle = 'API-Zugang';
$activeNav = 'api_keys';
require __DIR__ . '/_layout_top.php';
?>

<?php if ($newKey !== ''): ?>
    <div class="alert warning">
        <strong>Neuer API-Schlüssel (wird nur jetzt angezeigt, bitte sofort kopieren):</strong><br>
        <span class="mono" id="new-key"><?= htmlspecialchars($newKey) ?></span>
        <button type="button" class="btn small" onclick="navigator.clipboard.writeText(document.getElementById('new-key').innerText)">Kopieren</button>
        <p class="muted">Diesen Schlüssel im C#-Admin-Client unter „Einstellungen“ zusammen mit der API-Adresse eintragen.</p>
    </div>
<?php endif; ?>

<div class="panel">
    <h2>Neuen API-Schlüssel erstellen</h2>
    <p class="muted">Für den C#-Admin-Client (VSRP DDoS Monitor). Die Anwendung greift ausschließlich lesend auf Status/Vorfälle zu und kann Verdächtige als bearbeitet markieren – sie kann keine Firewall-Regeln setzen.</p>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
        <input type="hidden" name="action" value="create">
        <div class="form-row" style="max-width:320px">
            <label>Bezeichnung</label>
            <input type="text" name="label" placeholder="z. B. Admin-PC Christian">
        </div>
        <button type="submit" class="btn primary">Schlüssel erstellen</button>
    </form>
</div>

<div class="panel">
    <h2>Bestehende Schlüssel</h2>
    <?php if (!$keys): ?>
        <p class="muted">Noch keine Schlüssel erstellt.</p>
    <?php else: ?>
        <table>
            <thead><tr><th>Bezeichnung</th><th>Erstellt</th><th>Zuletzt genutzt</th><th>Status</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($keys as $k): ?>
                <tr>
                    <td><?= htmlspecialchars($k['label']) ?></td>
                    <td><?= htmlspecialchars($k['created_at']) ?></td>
                    <td><?= htmlspecialchars($k['last_used_at'] ?? '–') ?></td>
                    <td><?= $k['revoked_at'] ? '<span class="badge ignored">widerrufen</span>' : '<span class="badge resolved">aktiv</span>' ?></td>
                    <td>
                        <?php if (!$k['revoked_at']): ?>
                            <form method="post" style="display:inline" onsubmit="return confirm('Schlüssel wirklich widerrufen?');">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
                                <input type="hidden" name="action" value="revoke">
                                <input type="hidden" name="id" value="<?= (int)$k['id'] ?>">
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
