<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

use Vsrp\Ddos\Models\Setting;

/**
 * Wertet Messungen eines Servers (server_id NULL = Hauptserver mit lokalem Collector) gegen die
 * Schwellwerte aus, verwaltet den Lebenszyklus eines Vorfalls und löst Benachrichtigungen aus.
 *
 * Erkennt zwei Fälle: (1) Schwellwert überschritten, (2) plötzlicher Anstieg gegenüber dem Durchschnitt
 * der letzten Messungen (Frühwarnung: ein DDoS "im Anmarsch"). Blockiert nichts automatisch – es werden
 * nur Befehlsvorschläge für auffällige IPs erzeugt.
 *
 * Zustand (aufeinanderfolgende Treffer, letzte Messwerte) wird von außen übergeben und zurückgegeben,
 * damit dieselbe Logik im Dauerprozess (Collector) und bei einzelnen API-Anfragen (Agenten) funktioniert.
 */
final class Detector
{
    public static function newState(): array
    {
        return ['over' => 0, 'under' => 0, 'hist_mbit' => [], 'hist_conn' => []];
    }

    public static function evaluate(array $metrics, ?int $serverId, array $state): array
    {
        $state += self::newState();

        $mbitThreshold = Setting::getFloat('mbit_threshold', 800);
        $ppsThreshold = Setting::getInt('pps_threshold', 150000);
        $connThreshold = Setting::getInt('total_conn_threshold', 2500);
        $synThreshold = Setting::getInt('syn_recv_threshold', 300);
        $perIpThreshold = Setting::getInt('per_ip_conn_threshold', 80);
        $toTrigger = max(1, Setting::getInt('consecutive_to_trigger', 3));
        $toResolve = max(1, Setting::getInt('consecutive_to_resolve', 6));

        $reasons = [];
        if ($metrics['mbit_in'] >= $mbitThreshold) {
            $reasons[] = sprintf('Bandbreite %.1f MBit/s ≥ %.1f MBit/s', $metrics['mbit_in'], $mbitThreshold);
        }
        if ($metrics['pps_in'] >= $ppsThreshold) {
            $reasons[] = sprintf('%d Pakete/s ≥ %d', $metrics['pps_in'], $ppsThreshold);
        }
        if ($metrics['total_conn'] >= $connThreshold) {
            $reasons[] = sprintf('%d Verbindungen ≥ %d', $metrics['total_conn'], $connThreshold);
        }
        if ($metrics['syn_recv'] >= $synThreshold) {
            $reasons[] = sprintf('%d SYN-RECV ≥ %d', $metrics['syn_recv'], $synThreshold);
        }
        $maxPerIp = 0;
        foreach ($metrics['per_ip'] as $stat) {
            $maxPerIp = max($maxPerIp, $stat['conn']);
        }
        if ($maxPerIp >= $perIpThreshold) {
            $reasons[] = sprintf('einzelne IP mit %d Verbindungen ≥ %d', $maxPerIp, $perIpThreshold);
        }

        // Frühwarnung: plötzlicher Anstieg gegenüber dem Durchschnitt der letzten Messungen
        $avgMbit = self::average($state['hist_mbit']);
        if (count($state['hist_mbit']) >= 3 && $metrics['mbit_in'] >= max($avgMbit * 5, $mbitThreshold * 0.2)) {
            $reasons[] = sprintf('plötzlicher Anstieg: %.1f MBit/s (Ø zuvor %.1f)', $metrics['mbit_in'], $avgMbit);
        }
        $avgConn = self::average($state['hist_conn']);
        if (count($state['hist_conn']) >= 3 && $metrics['total_conn'] >= max($avgConn * 5, $connThreshold * 0.2)) {
            $reasons[] = sprintf('plötzlicher Anstieg: %d Verbindungen (Ø zuvor %d)', $metrics['total_conn'], (int)$avgConn);
        }

        $state['hist_mbit'] = array_slice(array_merge($state['hist_mbit'], [$metrics['mbit_in']]), -6);
        $state['hist_conn'] = array_slice(array_merge($state['hist_conn'], [$metrics['total_conn']]), -6);

        if ($reasons) {
            $state['over']++;
            $state['under'] = 0;
        } else {
            $state['under']++;
            $state['over'] = 0;
        }

        $incidentId = self::activeIncidentId($serverId);
        if ($incidentId === null && $state['over'] >= $toTrigger) {
            $incidentId = self::startIncident($serverId, $metrics, implode('; ', $reasons));
        } elseif ($incidentId !== null) {
            self::updateIncident($incidentId, $metrics);
            if ($state['under'] >= $toResolve) {
                self::resolveIncident($incidentId);
                $incidentId = null;
            }
        }

        self::insertSample($serverId, $incidentId, $metrics);
        return $state;
    }

    /** Meldet Server, die sich nicht mehr melden (bei DDoS oft ein Zeichen für eine überlastete Leitung), und Rückkehr. */
    public static function checkOffline(): void
    {
        $db = Database::connection();
        $timeout = max(60, Setting::getInt('sample_interval_seconds', 10) * 6);
        $rows = $db->query('SELECT * FROM servers WHERE revoked_at IS NULL AND last_seen_at IS NOT NULL')->fetchAll();
        foreach ($rows as $row) {
            $silent = time() - strtotime($row['last_seen_at']) > $timeout;
            if ($silent && !(int)$row['offline_notified']) {
                Notifier::notifyServerOffline($row);
                $db->prepare('UPDATE servers SET offline_notified = 1 WHERE id = :id')->execute(['id' => $row['id']]);
            } elseif (!$silent && (int)$row['offline_notified']) {
                Notifier::notifyServerOnline($row);
                $db->prepare('UPDATE servers SET offline_notified = 0 WHERE id = :id')->execute(['id' => $row['id']]);
            }
        }
    }

    private static function average(array $values): float
    {
        return $values ? array_sum($values) / count($values) : 0.0;
    }

    private static function activeIncidentId(?int $serverId): ?int
    {
        $stmt = Database::connection()->prepare(
            "SELECT id FROM incidents WHERE status = 'active' AND server_id <=> :s ORDER BY id DESC LIMIT 1"
        );
        $stmt->execute(['s' => $serverId]);
        $row = $stmt->fetch();
        return $row ? (int)$row['id'] : null;
    }

    private static function startIncident(?int $serverId, array $metrics, string $reason): int
    {
        $db = Database::connection();
        $db->prepare(
            'INSERT INTO incidents (server_id, started_at, status, peak_mbit_in, peak_pps_in, peak_total_conn, peak_syn_recv, trigger_reason)
             VALUES (:server, NOW(), \'active\', :mbit, :pps, :conn, :syn, :reason)'
        )->execute([
            'server' => $serverId,
            'mbit' => $metrics['mbit_in'],
            'pps' => $metrics['pps_in'],
            'conn' => $metrics['total_conn'],
            'syn' => $metrics['syn_recv'],
            'reason' => $reason,
        ]);
        $incidentId = (int)$db->lastInsertId();

        $suspects = self::upsertSuspects($incidentId, $metrics);
        Notifier::notifyIncidentStarted(self::loadIncident($incidentId), $suspects);
        return $incidentId;
    }

    private static function updateIncident(int $incidentId, array $metrics): void
    {
        Database::connection()->prepare(
            'UPDATE incidents SET
                peak_mbit_in = GREATEST(peak_mbit_in, :mbit),
                peak_pps_in = GREATEST(peak_pps_in, :pps),
                peak_total_conn = GREATEST(peak_total_conn, :conn),
                peak_syn_recv = GREATEST(peak_syn_recv, :syn)
             WHERE id = :id'
        )->execute([
            'mbit' => $metrics['mbit_in'],
            'pps' => $metrics['pps_in'],
            'conn' => $metrics['total_conn'],
            'syn' => $metrics['syn_recv'],
            'id' => $incidentId,
        ]);
        self::upsertSuspects($incidentId, $metrics);
    }

    private static function resolveIncident(int $incidentId): void
    {
        Database::connection()->prepare("UPDATE incidents SET status = 'resolved', resolved_at = NOW() WHERE id = :id")
            ->execute(['id' => $incidentId]);
        Notifier::notifyIncidentResolved(self::loadIncident($incidentId));
    }

    private static function loadIncident(int $incidentId): array
    {
        $stmt = Database::connection()->prepare(
            'SELECT i.*, s.name AS server_name FROM incidents i LEFT JOIN servers s ON s.id = i.server_id WHERE i.id = :id'
        );
        $stmt->execute(['id' => $incidentId]);
        $row = $stmt->fetch();
        $row['server_name'] = $row['server_name'] ?? 'Hauptserver';
        return $row;
    }

    /** Legt/aktualisiert die Top-Verdächtigen für den Vorfall an und liefert die Top 25. */
    private static function upsertSuspects(int $incidentId, array $metrics): array
    {
        $perIp = $metrics['per_ip'];
        uasort($perIp, static fn($a, $b) => $b['conn'] <=> $a['conn']);
        $top = array_slice($perIp, 0, 25, true);

        $stmt = Database::connection()->prepare(
            'INSERT INTO suspects (incident_id, ip, conn_count, syn_recv_count, first_seen_at, last_seen_at, suggested_cmd_nft, suggested_cmd_iptables)
             VALUES (:incident_id, :ip, :conn, :syn, NOW(), NOW(), :nft, :ipt)
             ON DUPLICATE KEY UPDATE
                conn_count = VALUES(conn_count),
                syn_recv_count = VALUES(syn_recv_count),
                last_seen_at = NOW()'
        );
        $result = [];
        foreach ($top as $ip => $stat) {
            if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                continue; // Befehle nur für gültige IP-Adressen erzeugen (Agent-Eingaben nicht blind vertrauen)
            }
            $stmt->execute([
                'incident_id' => $incidentId,
                'ip' => $ip,
                'conn' => (int)$stat['conn'],
                'syn' => (int)$stat['syn'],
                'nft' => "nft add rule inet filter input ip saddr $ip drop",
                'ipt' => "iptables -I INPUT -s $ip -j DROP",
            ]);
            $result[] = ['ip' => $ip, 'conn_count' => (int)$stat['conn'], 'syn_recv_count' => (int)$stat['syn']];
        }
        return $result;
    }

    private static function insertSample(?int $serverId, ?int $incidentId, array $metrics): void
    {
        Database::connection()->prepare(
            'INSERT INTO samples (ts, mbit_in, pps_in, mbit_out, pps_out, total_conn, syn_recv, incident_id, server_id)
             VALUES (NOW(), :mbit_in, :pps_in, :mbit_out, :pps_out, :conn, :syn, :incident_id, :server_id)'
        )->execute([
            'mbit_in' => $metrics['mbit_in'],
            'pps_in' => $metrics['pps_in'],
            'mbit_out' => $metrics['mbit_out'],
            'pps_out' => $metrics['pps_out'],
            'conn' => $metrics['total_conn'],
            'syn' => $metrics['syn_recv'],
            'incident_id' => $incidentId,
            'server_id' => $serverId,
        ]);
    }

    public static function pruneOldSamples(): void
    {
        $days = max(1, Setting::getInt('samples_retention_days', 14));
        Database::connection()
            ->prepare('DELETE FROM samples WHERE ts < DATE_SUB(NOW(), INTERVAL :d DAY) AND incident_id IS NULL')
            ->execute(['d' => $days]);
    }
}
