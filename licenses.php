<?php

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Database;
use Vsrp\Ddos\License;

Auth::requireLogin();

$db = Database::connection();
$newKey = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && Auth::checkCsrf()) {
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'create') {
        $label = trim((string)($_POST['label'] ?? '')) ?: 'Admin-PC';
        $expires = trim((string)($_POST['expires_at'] ?? ''));
        $expires = preg_match('/^\d{4}-\d{2}-\d{2}$/', $expires) ? $expires : null;
        $newKey = License::newKey();
        $db->prepare('INSERT INTO licenses (label, key_hash, key_hint, expires_at) VALUES (:l, :h, :hint, :e)')
            ->execute(['l' => $label, 'h' => License::hash($newKey), 'hint' => substr($newKey, -4), 'e' => $expires]);
    } elseif ($action === 'revoke') {
        $db->prepare('UPDATE licenses SET revoked_at = NOW() WHERE id = :id')->execute(['id' => (int)($_POST['id'] ?? 0)]);
    }
}

$licenses = $db->query('SELECT * FROM licenses ORDER BY id DESC')->fetchAll();

$pageTitle = 'Lizenzen';
$activeNav = 'licenses';
require __DIR__ . '/_layout_top.php';
?>

<?php if ($newKey !== ''): ?>
    <div class="alert warning">
        <strong>Neuer Lizenzschlüssel (wird nur jetzt angezeigt, bitte sofort kopieren):</strong><br>
        <span class="mono" id="new-key"><?= htmlspecialchars($newKey) ?></span>
        <button type="button" class="btn small" onclick="navigator.clipboard.writeText(document.getElementById('new-key').innerText)">Kopieren</button>
    </div>
<?php endif; ?>

<div class="panel">
    <h2>Neue Lizenz erstellen</h2>
    <p class="muted">Der C#-Admin-Client benötigt einen gültigen Lizenzschlüssel <em>und</em> einen API-Schlüssel.</p>
    <form method="post">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
        <input type="hidden" name="action" value="create">
        <div class="grid-2">
            <div class="form-row"><label>Bezeichnung</label><input type="text" name="label" placeholder="z. B. Admin-PC Christian"></div>
            <div class="form-row"><label>Gültig bis (optional)</label><input type="date" name="expires_at"></div>
        </div>
        <button type="submit" class="btn primary">Lizenz erstellen</button>
    </form>
</div>

<div class="panel">
    <h2>Bestehende Lizenzen</h2>
    <?php if (!$licenses): ?>
        <p class="muted">Noch keine Lizenzen erstellt.</p>
    <?php else: ?>
        <table>
            <thead><tr><th>Bezeichnung</th><th>Schlüssel</th><th>Erstellt</th><th>Gültig bis</th><th>Zuletzt genutzt</th><th>Status</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($licenses as $l): ?>
                <?php $expired = $l['expires_at'] !== null && $l['expires_at'] < date('Y-m-d'); ?>
                <tr>
                    <td><?= htmlspecialchars($l['label']) ?></td>
                    <td class="mono">VDOS-…-<?= htmlspecialchars($l['key_hint']) ?></td>
                    <td><?= htmlspecialchars($l['created_at']) ?></td>
                    <td><?= htmlspecialchars($l['expires_at'] ?? 'unbegrenzt') ?></td>
                    <td><?= htmlspecialchars($l['last_used_at'] ?? '–') ?></td>
                    <td>
                        <?php if ($l['revoked_at']): ?><span class="badge ignored">widerrufen</span>
                        <?php elseif ($expired): ?><span class="badge pending">abgelaufen</span>
                        <?php else: ?><span class="badge resolved">aktiv</span><?php endif; ?>
                    </td>
                    <td>
                        <?php if (!$l['revoked_at']): ?>
                            <form method="post" style="display:inline" onsubmit="return confirm('Lizenz wirklich widerrufen?');">
                                <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
                                <input type="hidden" name="action" value="revoke">
                                <input type="hidden" name="id" value="<?= (int)$l['id'] ?>">
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
