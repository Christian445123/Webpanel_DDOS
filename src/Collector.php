<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

/**
 * Liest Netzwerkmetriken vom Betriebssystem (Linux). Rein lesend, greift nicht in
 * die Firewall ein und stört den laufenden Spiele-Server nicht.
 */
final class Collector
{
    private ?array $prevCounters = null;
    private ?float $prevTime = null;

    /**
     * Eine Messung: Bandbreite (aus der Differenz zur vorherigen Messung) + aktueller
     * Verbindungs-Schnappschuss. Beim allerersten Aufruf ist die Bandbreite 0 (keine Referenz).
     */
    public function sample(string $iface): array
    {
        $now = microtime(true);
        $devContent = @file_get_contents('/proc/net/dev') ?: '';
        $counters = IpUtils::readInterfaceCounters($devContent, $iface);

        $mbitIn = 0.0;
        $ppsIn = 0;
        $mbitOut = 0.0;
        $ppsOut = 0;

        if ($counters !== null && $this->prevCounters !== null && $this->prevTime !== null) {
            $elapsed = max(0.001, $now - $this->prevTime);
            $rxBytesDelta = max(0, $counters['rx_bytes'] - $this->prevCounters['rx_bytes']);
            $rxPacketsDelta = max(0, $counters['rx_packets'] - $this->prevCounters['rx_packets']);
            $txBytesDelta = max(0, $counters['tx_bytes'] - $this->prevCounters['tx_bytes']);
            $txPacketsDelta = max(0, $counters['tx_packets'] - $this->prevCounters['tx_packets']);

            $mbitIn = ($rxBytesDelta * 8) / 1_000_000 / $elapsed;
            $ppsIn = (int)round($rxPacketsDelta / $elapsed);
            $mbitOut = ($txBytesDelta * 8) / 1_000_000 / $elapsed;
            $ppsOut = (int)round($txPacketsDelta / $elapsed);
        }

        if ($counters !== null) {
            $this->prevCounters = $counters;
            $this->prevTime = $now;
        }

        $ssOutput = self::runSs();
        $conn = IpUtils::parseSsOutput($ssOutput);

        return [
            'mbit_in' => round($mbitIn, 3),
            'pps_in' => $ppsIn,
            'mbit_out' => round($mbitOut, 3),
            'pps_out' => $ppsOut,
            'total_conn' => $conn['total'],
            'syn_recv' => $conn['synRecv'],
            'per_ip' => $conn['perIp'],
            'interface_found' => $counters !== null,
        ];
    }

    private static function runSs(): string
    {
        if (!function_exists('shell_exec')) {
            return '';
        }
        $output = @shell_exec('ss -Htan 2>/dev/null');
        return $output === null ? '' : $output;
    }
}
