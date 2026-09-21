<?php

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Database;

Auth::requireLogin();

$incidents = Database::connection()->query("SELECT i.*, COALESCE(s.name, 'Hauptserver') AS server_name FROM incidents i LEFT JOIN servers s ON s.id = i.server_id ORDER BY i.id DESC LIMIT 200")->fetchAll();

$pageTitle = 'Vorfälle';
$activeNav = 'incidents';
require __DIR__ . '/_layout_top.php';
?>

<div class="panel">
    <h2>Alle Vorfälle</h2>
    <?php if (!$incidents): ?>
        <p class="muted">Noch keine Vorfälle aufgezeichnet.</p>
    <?php else: ?>
        <table>
            <thead>
            <tr>
                <th>#</th><th>Server</th><th>Beginn</th><th>Ende</th><th>Status</th>
                <th>Spitze MBit/s</th><th>Spitze pps</th><th>Spitze Verb.</th><th>Auslöser</th><th></th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($incidents as $inc): ?>
                <tr>
                    <td><?= (int)$inc['id'] ?></td>
                    <td><?= htmlspecialchars($inc['server_name']) ?></td>
                    <td><?= htmlspecialchars($inc['started_at']) ?></td>
                    <td><?= htmlspecialchars($inc['resolved_at'] ?? '–') ?></td>
                    <td><span class="badge <?= htmlspecialchars($inc['status']) ?>"><?= htmlspecialchars($inc['status']) ?></span></td>
                    <td><?= number_format((float)$inc['peak_mbit_in'], 1, ',', '.') ?></td>
                    <td><?= number_format((int)$inc['peak_pps_in'], 0, ',', '.') ?></td>
                    <td><?= number_format((int)$inc['peak_total_conn'], 0, ',', '.') ?></td>
                    <td class="muted"><?= htmlspecialchars($inc['trigger_reason']) ?></td>
                    <td><a href="/incident.php?id=<?= (int)$inc['id'] ?>">Details</a></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/_layout_bottom.php'; ?>
