<?php

declare(strict_types=1);

require dirname(__DIR__) . '/autoload.php';

use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Database;
use Vsrp\Ddos\Models\Setting;

Auth::requireLogin();

$db = Database::connection();
$latest = $db->query('SELECT * FROM samples ORDER BY id DESC LIMIT 1')->fetch();
$active = $db->query("SELECT * FROM incidents WHERE status = 'active' ORDER BY id DESC LIMIT 1")->fetch();
$recentSamples = array_reverse($db->query(
    'SELECT ts, mbit_in, pps_in, total_conn, syn_recv FROM samples ORDER BY id DESC LIMIT 180'
)->fetchAll());
$recentIncidents = $db->query('SELECT * FROM incidents ORDER BY id DESC LIMIT 5')->fetchAll();

$mbitThreshold = Setting::getFloat('mbit_threshold', 800);

$pageTitle = 'Dashboard';
$activeNav = 'dashboard';
require __DIR__ . '/_layout_top.php';
?>

<?php if ($active): ?>
    <div class="alert error">
        ⚠️ <strong>Aktiver Vorfall #<?= (int)$active['id'] ?></strong> seit <?= htmlspecialchars($active['started_at']) ?>
        — <?= htmlspecialchars($active['trigger_reason']) ?>
        &nbsp; <a href="/incident.php?id=<?= (int)$active['id'] ?>">Details ansehen →</a>
    </div>
<?php elseif (!$latest): ?>
    <div class="alert warning">
        Noch keine Messwerte vorhanden. Läuft der Collector-Dienst? Siehe <code>systemd/vsrp-ddos-collector.service</code>.
    </div>
<?php else: ?>
    <div class="alert success">✅ Kein aktiver Vorfall — Netzwerk unauffällig.</div>
<?php endif; ?>

<div class="cards">
    <div class="card">
        <div class="label">Eingehend</div>
        <div class="value <?= $latest && (float)$latest['mbit_in'] >= $mbitThreshold ? 'danger' : '' ?>">
            <?= $latest ? number_format((float)$latest['mbit_in'], 1, ',', '.') : '–' ?> <span style="font-size:14px">MBit/s</span>
        </div>
    </div>
    <div class="card">
        <div class="label">Pakete/s (eingehend)</div>
        <div class="value"><?= $latest ? number_format((int)$latest['pps_in'], 0, ',', '.') : '–' ?></div>
    </div>
    <div class="card">
        <div class="label">Aktive Verbindungen</div>
        <div class="value"><?= $latest ? number_format((int)$latest['total_conn'], 0, ',', '.') : '–' ?></div>
    </div>
    <div class="card">
        <div class="label">SYN-RECV</div>
        <div class="value"><?= $latest ? number_format((int)$latest['syn_recv'], 0, ',', '.') : '–' ?></div>
    </div>
</div>

<div class="panel">
    <h2>Verlauf (letzte Messungen)</h2>
    <canvas id="trafficChart" height="90"></canvas>
</div>

<div class="panel">
    <h2>Letzte Vorfälle</h2>
    <?php if (!$recentIncidents): ?>
        <p class="muted">Noch keine Vorfälle aufgezeichnet.</p>
    <?php else: ?>
        <table>
            <thead><tr><th>#</th><th>Beginn</th><th>Ende</th><th>Status</th><th>Spitze MBit/s</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($recentIncidents as $inc): ?>
                <tr>
                    <td><?= (int)$inc['id'] ?></td>
                    <td><?= htmlspecialchars($inc['started_at']) ?></td>
                    <td><?= htmlspecialchars($inc['resolved_at'] ?? '–') ?></td>
                    <td><span class="badge <?= htmlspecialchars($inc['status']) ?>"><?= htmlspecialchars($inc['status']) ?></span></td>
                    <td><?= number_format((float)$inc['peak_mbit_in'], 1, ',', '.') ?></td>
                    <td><a href="/incident.php?id=<?= (int)$inc['id'] ?>">Details</a></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<script>
const samples = <?= json_encode($recentSamples) ?>;
const ctx = document.getElementById('trafficChart');
new Chart(ctx, {
    type: 'line',
    data: {
        labels: samples.map(s => s.ts.substring(11, 19)),
        datasets: [
            { label: 'MBit/s eingehend', data: samples.map(s => parseFloat(s.mbit_in)), borderColor: '#4f8cff', tension: .25, pointRadius: 0 },
            { label: 'Verbindungen', data: samples.map(s => parseInt(s.total_conn)), borderColor: '#f39c12', tension: .25, pointRadius: 0, yAxisID: 'y1' },
        ]
    },
    options: {
        responsive: true,
        interaction: { mode: 'index', intersect: false },
        scales: {
            y: { beginAtZero: true, ticks: { color: '#8b94ab' }, grid: { color: '#2a3247' } },
            y1: { beginAtZero: true, position: 'right', ticks: { color: '#8b94ab' }, grid: { display: false } },
            x: { ticks: { color: '#8b94ab', maxTicksLimit: 12 }, grid: { display: false } },
        },
        plugins: { legend: { labels: { color: '#e6e9f0' } } },
    }
});
</script>

<?php require __DIR__ . '/_layout_bottom.php'; ?>
