#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Läuft dauerhaft im Hintergrund (als systemd-Dienst, siehe systemd/vsrp-ddos-collector.service)
 * und misst in einer Schleife Netzwerk-Metriken. Greift nicht in die Firewall ein und
 * beeinflusst den Spiele-Server nicht — reine Beobachtung + Alarmierung.
 *
 * Aufruf: php bin/collector.php
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Nur über die Kommandozeile ausführbar.');
}

require dirname(__DIR__) . '/autoload.php';

use Vsrp\Ddos\Collector;
use Vsrp\Ddos\Detector;
use Vsrp\Ddos\Models\Setting;

$running = true;
if (function_exists('pcntl_signal')) {
    pcntl_async_signals(true);
    $stop = static function () use (&$running) { $running = false; };
    pcntl_signal(SIGTERM, $stop);
    pcntl_signal(SIGINT, $stop);
}

$collector = new Collector();
$detectorState = Detector::newState();
$lastPrune = 0;

// Nach einem Update über die Web-Oberfläche (update.php) wird .update-stamp neu geschrieben: der Dienst beendet sich dann
// und wird von systemd (Restart=always) automatisch mit dem neuen Code gestartet.
$stampFile = dirname(__DIR__) . '/.update-stamp';
$readStamp = static function () use ($stampFile): string {
    clearstatcache(true, $stampFile);
    return is_file($stampFile) ? (string)@file_get_contents($stampFile) : '';
};
$startStamp = $readStamp();

fwrite(STDOUT, '[VSRP-DDoS] Collector gestartet, PID ' . getmypid() . "\n");

while ($running) {
    if ($readStamp() !== $startStamp) {
        fwrite(STDOUT, "[VSRP-DDoS] Update erkannt, Dienst startet neu.\n");
        break;
    }
    Setting::refresh(); // im Web-UI geänderte Einstellungen (Schwellwerte etc.) ohne Neustart übernehmen
    $intervalSeconds = max(2, Setting::getInt('sample_interval_seconds', 10));
    $iface = Setting::get('monitor_interface', 'eth0');

    try {
        $metrics = $collector->sample($iface);
        if (!$metrics['interface_found']) {
            fwrite(STDERR, "[VSRP-DDoS] Warnung: Netzwerkschnittstelle '$iface' nicht gefunden (siehe Einstellungen).\n");
        }
        $detectorState = Detector::evaluate($metrics, null, $detectorState);
        Detector::checkOffline();
    } catch (\Throwable $e) {
        fwrite(STDERR, '[VSRP-DDoS] Fehler im Messzyklus: ' . $e->getMessage() . "\n");
    }

    if (time() - $lastPrune > 3600) {
        try {
            Detector::pruneOldSamples();
        } catch (\Throwable $e) {
            fwrite(STDERR, '[VSRP-DDoS] Fehler beim Aufräumen alter Messwerte: ' . $e->getMessage() . "\n");
        }
        $lastPrune = time();
    }

    if (function_exists('pcntl_signal_dispatch')) {
        pcntl_signal_dispatch();
    }
    if ($running) {
        sleep($intervalSeconds);
    }
}

fwrite(STDOUT, "[VSRP-DDoS] Collector beendet.\n");
