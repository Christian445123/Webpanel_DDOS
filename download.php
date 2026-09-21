<?php

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Vsrp\Ddos\Auth;
use Vsrp\Ddos\Config;
use Vsrp\Ddos\Release;

Auth::requireLogin();

$release = Release::latest();

// Stabiler Link: /download.php?get=1 leitet direkt auf die neueste MSI-Datei weiter
if (isset($_GET['get']) && $release !== null) {
    header('Location: ' . $release['asset_url']);
    exit;
}

$repo = (string)Config::get('github_repo', '');
$pageTitle = 'Download';
$activeNav = 'download';
require __DIR__ . '/_layout_top.php';
?>

<div class="panel">
    <h2>Windows-Client herunterladen</h2>
    <?php if ($release === null): ?>
        <div class="alert warning">
            Die neueste Version konnte gerade nicht von GitHub abgerufen werden
            <?php if ($repo !== ''): ?>
                – <a href="https://github.com/<?= htmlspecialchars($repo) ?>/releases/latest" target="_blank" rel="noopener">Releases direkt auf GitHub öffnen</a>.
            <?php else: ?>
                (GITHUB_REPO ist in der .env nicht gesetzt).
            <?php endif; ?>
        </div>
    <?php else: ?>
        <p>
            Neueste Version: <strong><?= htmlspecialchars($release['version']) ?></strong>
            <span class="muted">
                · veröffentlicht am <?= htmlspecialchars(date('d.m.Y', strtotime($release['published']) ?: time())) ?>
                · <?= htmlspecialchars(number_format($release['asset_size'] / 1048576, 1, ',', '.')) ?> MB
            </span>
        </p>
        <p>
            <a class="btn primary" href="/download.php?get=1">⬇ <?= htmlspecialchars($release['asset_name']) ?> herunterladen</a>
            <a class="btn" href="<?= htmlspecialchars($release['url']) ?>" target="_blank" rel="noopener">Versionshinweise auf GitHub</a>
        </p>
        <?php if (trim($release['notes']) !== ''): ?>
            <h2 style="margin-top:22px">Neu in dieser Version</h2>
            <pre class="mono" style="white-space:pre-wrap"><?= htmlspecialchars($release['notes']) ?></pre>
        <?php endif; ?>
    <?php endif; ?>
</div>

<div class="panel">
    <h2>Installation</h2>
    <ol>
        <li>Die <code>.msi</code>-Datei ausführen (Windows fragt einmal nach Administratorrechten).</li>
        <li>Lizenzschlüssel (Menü „Lizenzen“) und API-Schlüssel (Menü „API-Zugang“) eintragen.</li>
        <li>Das Programm aktualisiert sich später selbst: Bei einer neuen Version erscheint ein Dialog mit „Jetzt aktualisieren“.</li>
    </ol>
    <p class="muted">Voraussetzung: Windows 10/11 mit .NET Framework 4.8 (in Windows enthalten).</p>
</div>

<?php require __DIR__ . '/_layout_bottom.php'; ?>
