<?php

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Vsrp\Ddos\Auth;
use Vsrp\Ddos\GitUpdater;

Auth::requireLogin();

$available = GitUpdater::available();
$result = null;
$action = '';

if ($available && $_SERVER['REQUEST_METHOD'] === 'POST' && Auth::checkCsrf()) {
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'check') {
        $result = GitUpdater::checkForUpdates();
    } elseif ($action === 'pull') {
        $result = GitUpdater::pull();
    }
}

$pageTitle = 'Update';
$activeNav = 'update';
require __DIR__ . '/_layout_top.php';
?>

<div class="panel">
    <h2>Anwendung aktualisieren (git pull)</h2>
    <?php if (!$available): ?>
        <div class="alert warning">
            Diese Funktion ist auf dem Server nicht verfügbar: Es wird ein Git-Repository im App-Ordner, das Programm
            <code>git</code> und die PHP-Funktion <code>proc_open</code> (nicht in <code>disable_functions</code>) benötigt.
        </div>
    <?php else: ?>
        <p>
            <strong>Aktueller Stand:</strong> <span class="mono"><?= htmlspecialchars(GitUpdater::currentCommit()) ?></span><br>
            <strong>Branch:</strong> <span class="mono"><?= htmlspecialchars(GitUpdater::branch()) ?></span>
        </p>

        <form method="post" style="display:inline">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
            <input type="hidden" name="action" value="check">
            <button type="submit" class="btn">Auf Updates prüfen</button>
        </form>
        <form method="post" style="display:inline" onsubmit="return confirm('Jetzt git pull ausführen und die Anwendung aktualisieren?');">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars(Auth::csrfToken()) ?>">
            <input type="hidden" name="action" value="pull">
            <button type="submit" class="btn primary">Jetzt aktualisieren (git pull)</button>
        </form>

        <?php if ($action === 'check' && $result !== null): ?>
            <?php if ($result['behind'] === null): ?>
                <div class="alert error" style="margin-top:16px">Prüfung fehlgeschlagen:<pre class="mono" style="white-space:pre-wrap"><?= htmlspecialchars($result['output']) ?></pre></div>
            <?php elseif ($result['behind'] === 0): ?>
                <div class="alert success" style="margin-top:16px">✅ Die Anwendung ist auf dem neuesten Stand.</div>
            <?php else: ?>
                <div class="alert warning" style="margin-top:16px">
                    ⬆ <?= (int)$result['behind'] ?> neue Änderung(en) verfügbar:
                    <pre class="mono" style="white-space:pre-wrap"><?= htmlspecialchars($result['output']) ?></pre>
                </div>
            <?php endif; ?>
        <?php elseif ($action === 'pull' && $result !== null): ?>
            <div class="alert <?= $result['code'] === 0 ? 'success' : 'error' ?>" style="margin-top:16px">
                <?= $result['code'] === 0 ? '✅ Update durchgeführt. Der Collector-Dienst startet sich innerhalb weniger Sekunden selbst mit dem neuen Code neu.' : '❌ git pull ist fehlgeschlagen (Exit-Code ' . (int)$result['code'] . ').' ?>
                <pre class="mono" style="white-space:pre-wrap"><?= htmlspecialchars($result['output']) ?></pre>
            </div>
        <?php endif; ?>

        <p class="muted" style="margin-top:18px">
            Es wird ausschließlich <code>git pull --ff-only</code> im App-Ordner ausgeführt. Lokale, nicht committete Änderungen
            auf dem Server führen zu einem Abbruch (nichts wird überschrieben). Die <code>.env</code> wird von Git nie angefasst.
        </p>
    <?php endif; ?>
</div>

<?php require __DIR__ . '/_layout_bottom.php'; ?>
