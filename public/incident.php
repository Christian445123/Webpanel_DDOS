<?php

declare(strict_types=1);

require dirname(__DIR__) . '/autoload.php';

use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Database;

Auth::requireLogin();

$id = (int)($_GET['id'] ?? 0);
$db = Database::connection();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && Auth::checkCsrf()) {
    $suspectId = (int)($_POST['suspect_id'] ?? 0);
    $action = (string)($_POST['action'] ?? '');
    if (in_array($action, ['manual_blocked', 'ignored', 'pending'], true) && $suspectId > 0) {
        $stmt = $db->prepare(
            'UPDATE suspects SET status = :s, status_updated_by = :by, status_updated_at = NOW() WHERE id = :id AND incident_id = :inc'
        );
        $stmt->execute(['s' => $action, 'by' => Auth::username(), 'id' => $suspectId, 'inc' => $id]);
    }
    header('Location: /incident.php?id=' . $id);
    exit;
}

$incident = $db->prepare('SELECT * FROM incidents WHERE id = :id');
$incident->execute(['id' => $id]);
$incident = $incident->fetch();
if (!$incident) {
    http_response_code(404);
    exit('Vorfall nicht gefunden.');
}

$suspectsStmt = $db->prepare('SELECT * FROM suspects WHERE incident_id = :id ORDER BY conn_count DESC');
$suspectsStmt->execute(['id' => $id]);
$suspects = $suspectsStmt->fetchAll();

$pageTitle = 'Vorfall #' . $id;
$activeNav = 'incidents';
require __DIR__ . '/_layout_top.php';
?>

<p><a href="/incidents.php">← Alle Vorfälle</a></p>

<div class="panel">
    <h2>Vorfall #<?= (int)$incident['id'] ?> <span class="badge <?= htmlspecialchars($incident['status']) ?>"><?= htmlspecialchars($incident['status']) ?></span></h2>
    <div class="grid-2">
        <div>
            <p><strong>Beginn:</strong> <?= htmlspecialchars($incident['started_at']) ?></p>
            <p><strong>Ende:</strong> <?= htmlspecialchars($incident['resolved_at'] ?? '– (noch aktiv)') ?></p>
            <p><strong>Auslöser:</strong> <?= htmlspecialchars($incident['trigger_reason']) ?></p>
        </div>
        <div>
            <p><strong>Spitze Bandbreite:</strong> <?= number_format((float)$incident['peak_mbit_in'], 1, ',', '.') ?> MBit/s</p>
            <p><strong>Spitze Pakete/s:</strong> <?= number_format((int)$incident['peak_pps_in'], 0, ',', '.') ?></p>
            <p><strong>Spitze Verbindungen:</strong> <?= number_format((int)$incident['peak_total_conn'], 0, ',', '.') ?>
                (davon max. SYN-RECV: <?= number_format((int)$incident['peak_syn_recv'], 0, ',', '.') ?>)</p>
        </div>
    </div>
    <p class="muted">
        Benachrichtigt:
        E-Mail <?= $incident['notified_email'] ? '✅' : '❌' ?> ·
        Discord <?= $incident['notified_discord'] ? '✅' : '❌' ?>
    </p>
</div>

<div class="panel">
    <h2>Auffällige IP-Adressen</h2>
    <p class="muted">
        Diese Befehle werden <strong>nicht automatisch ausgeführt</strong>. Bei Bedarf per SSH auf dem Server manuell
        ausführen und danach hier als „blockiert“ markieren.
    </p>
    <?php if (!$suspects): ?>
        <p class="muted">Keine auffälligen Einzel-IPs erfasst.</p>
    <?php else: ?>
        <table>
            <thead>
            <tr><th>IP</th><th>Verbindungen</th><th>SYN-RECV</th><th>Vorschlag (nftables)</th><th>Status</th><th></th></tr>
            </thead>
            <tbody>
            <?php foreach ($suspects as $s): ?>
                <tr>
                    <td class="mono"><?= htmlspecialchars($s['ip']) ?></td>
                    <td><?= (int)$s['conn_count'] ?></td>
                    <td><?= (int)$s['syn_recv_count'] ?></td>
                    <td>
                        <span class="mono" id="cmd-<?= (int)$s['id'] ?>"><?= htmlspecialchars($s['suggested_cmd_nft']) ?></span>
                        <button type="button" class="btn small" onclick="copyCmd(<?= (int)$s['id'] ?>)">Kopieren</button>
                    </td>
                    <td><span class="badge <?= htmlspecialchars($s['status']) ?>"><?= htmlspecialchars($s['status']) ?></span></td>
                    <td>
                        <form method="post" style="display:inline">
                            <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
                            <input type="hidden" name="suspect_id" value="<?= (int)$s['id'] ?>">
                            <?php if ($s['status'] !== 'manual_blocked'): ?>
                                <button type="submit" name="action" value="manual_blocked" class="btn small">Als blockiert markieren</button>
                            <?php endif; ?>
                            <?php if ($s['status'] !== 'ignored'): ?>
                                <button type="submit" name="action" value="ignored" class="btn small">Ignorieren</button>
                            <?php endif; ?>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<script>
function copyCmd(id) {
    const text = document.getElementById('cmd-' + id).innerText;
    navigator.clipboard.writeText(text).catch(() => {});
}
</script>

<?php require __DIR__ . '/_layout_bottom.php'; ?>
