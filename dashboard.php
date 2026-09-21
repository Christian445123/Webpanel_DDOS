<?php

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Database;
use Vsrp\Ddos\Models\Setting;

Auth::requireLogin();

$db = Database::connection();

// Auswahl: 0 = Hauptserver (lokaler Collector), sonst ID eines überwachten Servers
$allServers = $db->query('SELECT * FROM servers WHERE revoked_at IS NULL ORDER BY name')->fetchAll();
$serverId = (int)($_GET['server'] ?? 0);
$selected = null;
foreach ($allServers as $s) {
    if ((int)$s['id'] === $serverId) {
        $selected = $s;
    }
}
if ($selected === null) {
    $serverId = 0;
}
$sid = $serverId > 0 ? $serverId : null;
$serverName = $selected['name'] ?? 'Hauptserver';

$latestStmt = $db->prepare('SELECT * FROM samples WHERE server_id <=> :s ORDER BY id DESC LIMIT 1');
$latestStmt->execute(['s' => $sid]);
$latest = $latestStmt->fetch();

$activeStmt = $db->prepare("SELECT * FROM incidents WHERE status = 'active' AND server_id <=> :s ORDER BY id DESC LIMIT 1");
$activeStmt->execute(['s' => $sid]);
$active = $activeStmt->fetch();

$samplesStmt = $db->prepare(
    'SELECT ts, mbit_in, mbit_out, pps_in, pps_out, total_conn, syn_recv FROM samples WHERE server_id <=> :s ORDER BY id DESC LIMIT 180'
);
$samplesStmt->execute(['s' => $sid]);
$recentSamples = array_reverse($samplesStmt->fetchAll());

$incStmt = $db->prepare('SELECT * FROM incidents WHERE server_id <=> :s ORDER BY id DESC LIMIT 5');
$incStmt->execute(['s' => $sid]);
$recentIncidents = $incStmt->fetchAll();

// Übersicht aller Server (nur in der Hauptansicht)
$overview = $db->query(
    "SELECT s.*, (SELECT COUNT(*) FROM incidents i WHERE i.server_id = s.id AND i.status = 'active') AS active_incidents,
            (SELECT mbit_in FROM samples x WHERE x.server_id = s.id ORDER BY x.id DESC LIMIT 1) AS last_mbit
     FROM servers s WHERE s.revoked_at IS NULL ORDER BY s.name"
)->fetchAll();

$mbitThreshold = Setting::getFloat('mbit_threshold', 800);
$fmt = static fn($v, int $d = 0): string => $v === null ? '–' : number_format((float)$v, $d, ',', '.');

$pageTitle = 'Dashboard – ' . $serverName;
$activeNav = 'dashboard';
require __DIR__ . '/_layout_top.php';
?>

<div style="margin-bottom:16px">
    <a class="btn small <?= $serverId === 0 ? 'primary' : '' ?>" href="/dashboard.php">Hauptserver</a>
    <?php foreach ($allServers as $s): ?>
        <a class="btn small <?= $serverId === (int)$s['id'] ? 'primary' : '' ?>" href="/dashboard.php?server=<?= (int)$s['id'] ?>"><?= htmlspecialchars($s['name']) ?></a>
    <?php endforeach; ?>
</div>

<?php if ($active): ?>
    <div class="alert error">
        ⚠️ <strong>Aktiver Vorfall #<?= (int)$active['id'] ?> auf <?= htmlspecialchars($serverName) ?></strong> seit <?= htmlspecialchars($active['started_at']) ?>
        — <?= htmlspecialchars($active['trigger_reason']) ?>
        &nbsp; <a href="/incident.php?id=<?= (int)$active['id'] ?>">Details ansehen →</a>
    </div>
<?php elseif (!$latest): ?>
    <div class="alert warning">
        Noch keine Messwerte von „<?= htmlspecialchars($serverName) ?>“.
        <?= $serverId === 0 ? 'Läuft der Collector-Dienst? Siehe <code>systemd/vsrp-ddos-collector.service</code>.' : 'Ist der Agent auf dem Server installiert (siehe Menüpunkt „Server“)?' ?>
    </div>
<?php else: ?>
    <div class="alert success">✅ <?= htmlspecialchars($serverName) ?>: kein aktiver Vorfall — Netzwerk unauffällig.
        <span class="muted">(letzte Messung <?= htmlspecialchars($latest['ts']) ?>)</span></div>
<?php endif; ?>

<div class="cards">
    <div class="card">
        <div class="label">Eingehend</div>
        <div class="value <?= $latest && (float)$latest['mbit_in'] >= $mbitThreshold ? 'danger' : '' ?>">
            <?= $latest ? $fmt($latest['mbit_in'], 1) : '–' ?> <span style="font-size:14px">MBit/s</span>
        </div>
    </div>
    <div class="card">
        <div class="label">Ausgehend</div>
        <div class="value"><?= $latest ? $fmt($latest['mbit_out'], 1) : '–' ?> <span style="font-size:14px">MBit/s</span></div>
    </div>
    <div class="card">
        <div class="label">Pakete/s eingehend</div>
        <div class="value"><?= $latest ? $fmt($latest['pps_in']) : '–' ?></div>
    </div>
    <div class="card">
        <div class="label">Pakete/s ausgehend</div>
        <div class="value"><?= $latest ? $fmt($latest['pps_out']) : '–' ?></div>
    </div>
    <div class="card">
        <div class="label">Aktive Verbindungen</div>
        <div class="value"><?= $latest ? $fmt($latest['total_conn']) : '–' ?></div>
    </div>
    <div class="card">
        <div class="label">SYN-RECV</div>
        <div class="value"><?= $latest ? $fmt($latest['syn_recv']) : '–' ?></div>
    </div>
</div>

<div class="panel">
    <h2>Datenrate – <?= htmlspecialchars($serverName) ?> (eingehend / ausgehend)</h2>
    <canvas id="rateChart" height="80"></canvas>
</div>

<div class="panel">
    <h2>Pakete pro Sekunde – <?= htmlspecialchars($serverName) ?> (eingehend / ausgehend)</h2>
    <canvas id="packetChart" height="80"></canvas>
</div>

<div class="panel">
    <h2>Verbindungen – <?= htmlspecialchars($serverName) ?></h2>
    <canvas id="connChart" height="60"></canvas>
</div>

<?php if ($serverId === 0 && $overview): ?>
<div class="panel">
    <h2>Überwachte Server</h2>
    <table>
        <thead><tr><th>Server</th><th>Zuletzt gemeldet</th><th>Eingehend</th><th>Status</th><th></th></tr></thead>
        <tbody>
        <?php foreach ($overview as $s): ?>
            <?php $seen = $s['last_seen_at'] ? strtotime($s['last_seen_at']) : null; $online = $seen !== null && time() - $seen < 90; ?>
            <tr>
                <td><?= htmlspecialchars($s['name']) ?></td>
                <td><?= htmlspecialchars($s['last_seen_at'] ?? 'noch nie') ?></td>
                <td><?= $s['last_mbit'] !== null ? $fmt($s['last_mbit'], 1) . ' MBit/s' : '–' ?></td>
                <td>
                    <?php if ((int)$s['active_incidents'] > 0): ?><span class="badge active">DDoS-Verdacht</span>
                    <?php elseif ($online): ?><span class="badge resolved">online</span>
                    <?php else: ?><span class="badge pending"><?= $seen === null ? 'wartet auf Agent' : 'keine Meldung' ?></span><?php endif; ?>
                </td>
                <td><a href="/dashboard.php?server=<?= (int)$s['id'] ?>">Dashboard →</a></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>

<div class="panel">
    <h2>Letzte Vorfälle – <?= htmlspecialchars($serverName) ?></h2>
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
const labels = samples.map(s => s.ts.substring(11, 19));
const axis = { ticks: { color: '#8b94ab' }, grid: { color: '#2a3247' }, beginAtZero: true };
const xAxis = { ticks: { color: '#8b94ab', maxTicksLimit: 12 }, grid: { display: false } };
const line = (label, key, color, parse = parseFloat) => ({ label, data: samples.map(s => parse(s[key])), borderColor: color, tension: .25, pointRadius: 0 });
const make = (id, datasets) => new Chart(document.getElementById(id), {
    type: 'line',
    data: { labels, datasets },
    options: {
        responsive: true,
        interaction: { mode: 'index', intersect: false },
        scales: { y: axis, x: xAxis },
        plugins: { legend: { labels: { color: '#e6e9f0' } } },
    },
});
make('rateChart', [line('MBit/s eingehend', 'mbit_in', '#4f8cff'), line('MBit/s ausgehend', 'mbit_out', '#2ecc71')]);
make('packetChart', [line('Pakete/s eingehend', 'pps_in', '#e74c3c', parseInt), line('Pakete/s ausgehend', 'pps_out', '#f39c12', parseInt)]);
make('connChart', [line('Verbindungen', 'total_conn', '#9b59b6', parseInt), line('SYN-RECV', 'syn_recv', '#e67e22', parseInt)]);
</script>

<?php require __DIR__ . '/_layout_bottom.php'; ?>
