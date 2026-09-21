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
$detector = new Detector();
$lastPrune = 0;

fwrite(STDOUT, '[VSRP-DDoS] Collector gestartet, PID ' . getmypid() . "\n");

while ($running) {
    Setting::refresh(); // im Web-UI geänderte Einstellungen (Schwellwerte etc.) ohne Neustart übernehmen
    $intervalSeconds = max(2, Setting::getInt('sample_interval_seconds', 10));
    $iface = Setting::get('monitor_interface', 'eth0');

    try {
        $metrics = $collector->sample($iface);
        if (!$metrics['interface_found']) {
            fwrite(STDERR, "[VSRP-DDoS] Warnung: Netzwerkschnittstelle '$iface' nicht gefunden (siehe Einstellungen).\n");
        }
        $detector->evaluate($metrics);
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
