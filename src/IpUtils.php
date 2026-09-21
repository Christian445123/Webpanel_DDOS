<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

final class IpUtils
{
    /**
     * Liest /proc/net/dev und liefert [rxBytes, rxPackets, txBytes, txPackets] für die angegebene
     * Schnittstelle, oder null, wenn sie nicht gefunden wurde.
     */
    public static function readInterfaceCounters(string $procNetDevContent, string $iface): ?array
    {
        foreach (explode("\n", $procNetDevContent) as $line) {
            $line = trim($line);
            if (!str_contains($line, ':')) {
                continue;
            }
            [$name, $rest] = explode(':', $line, 2);
            if (trim($name) !== $iface) {
                continue;
            }
            $cols = preg_split('/\s+/', trim($rest));
            // /proc/net/dev Spalten: bytes packets errs drop fifo frame compressed multicast | bytes packets ...
            if (count($cols) < 16) {
                return null;
            }
            return [
                'rx_bytes' => (float)$cols[0],
                'rx_packets' => (float)$cols[1],
                'tx_bytes' => (float)$cols[8],
                'tx_packets' => (float)$cols[9],
            ];
        }
        return null;
    }

    /**
     * Wertet die Ausgabe von `ss -Htan` aus.
     * @return array{total:int, synRecv:int, perIp:array<string,array{conn:int,syn:int}>}
     */
    public static function parseSsOutput(string $output): array
    {
        $total = 0;
        $synRecv = 0;
        $perIp = [];

        foreach (explode("\n", $output) as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $cols = preg_split('/\s+/', $line);
            if (count($cols) < 5) {
                continue;
            }
            $state = $cols[0];
            if ($state === 'LISTEN') {
                continue;
            }
            $peer = $cols[4];
            $ip = self::extractIp($peer);
            if ($ip === null || self::isLocal($ip)) {
                continue;
            }

            $total++;
            if (!isset($perIp[$ip])) {
                $perIp[$ip] = ['conn' => 0, 'syn' => 0];
            }
            $perIp[$ip]['conn']++;
            if ($state === 'SYN-RECV') {
                $synRecv++;
                $perIp[$ip]['syn']++;
            }
        }

        return ['total' => $total, 'synRecv' => $synRecv, 'perIp' => $perIp];
    }

    /** "1.2.3.4:443" -> "1.2.3.4"; "[::1]:443" -> "::1" */
    public static function extractIp(string $addrPort): ?string
    {
        if (str_starts_with($addrPort, '[')) {
            $end = strpos($addrPort, ']');
            return $end === false ? null : substr($addrPort, 1, $end - 1);
        }
        $pos = strrpos($addrPort, ':');
        if ($pos === false) {
            return null;
        }
        $ip = substr($addrPort, 0, $pos);
        return $ip === '*' ? null : $ip;
    }

    public static function isLocal(string $ip): bool
    {
        if ($ip === '127.0.0.1' || $ip === '::1' || $ip === '*') {
            return true;
        }
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return true; // unbekanntes Format: sicherheitshalber ignorieren statt fälschlich als Angreifer zählen
        }
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
}
