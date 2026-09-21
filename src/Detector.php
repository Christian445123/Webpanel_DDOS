<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

use Vsrp\Ddos\Models\Setting;

/**
 * Wertet Messungen gegen die konfigurierten Schwellwerte aus, verwaltet den Lebenszyklus
 * eines Vorfalls (aktiv/entwarnt) und löst Benachrichtigungen aus.
 *
 * Blockiert NICHTS automatisch: es werden lediglich Vorschläge (Befehle) für auffällige
 * IP-Adressen erzeugt, die ein Administrator manuell prüft und ausführt.
 */
final class Detector
{
    private int $consecutiveOver = 0;
    private int $consecutiveUnder = 0;
    private ?int $activeIncidentId = null;

    public function __construct()
    {
        $active = Database::connection()->query(
            "SELECT id FROM incidents WHERE status = 'active' ORDER BY id DESC LIMIT 1"
        )->fetch();
        $this->activeIncidentId = $active ? (int)$active['id'] : null;
    }

    public function evaluate(array $metrics): void
    {
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

        $isOver = count($reasons) > 0;

        if ($isOver) {
            $this->consecutiveOver++;
            $this->consecutiveUnder = 0;
        } else {
            $this->consecutiveUnder++;
            $this->consecutiveOver = 0;
        }

        if ($this->activeIncidentId === null && $this->consecutiveOver >= $toTrigger) {
            $this->startIncident($metrics, implode('; ', $reasons));
        } elseif ($this->activeIncidentId !== null) {
            $this->updateIncident($metrics);
            if ($this->consecutiveUnder >= $toResolve) {
                $this->resolveIncident();
            }
        }

        $this->insertSample($metrics);
    }

    private function startIncident(array $metrics, string $reason): void
    {
        $db = Database::connection();
        $stmt = $db->prepare(
            'INSERT INTO incidents (started_at, status, peak_mbit_in, peak_pps_in, peak_total_conn, peak_syn_recv, trigger_reason)
             VALUES (NOW(), \'active\', :mbit, :pps, :conn, :syn, :reason)'
        );
        $stmt->execute([
            'mbit' => $metrics['mbit_in'],
            'pps' => $metrics['pps_in'],
            'conn' => $metrics['total_conn'],
            'syn' => $metrics['syn_recv'],
            'reason' => $reason,
        ]);
        $this->activeIncidentId = (int)$db->lastInsertId();

        $suspects = $this->upsertSuspects($metrics);

        $incident = $db->query('SELECT * FROM incidents WHERE id = ' . $this->activeIncidentId)->fetch();
        Notifier::notifyIncidentStarted($incident, $suspects);
    }

    private function updateIncident(array $metrics): void
    {
        $db = Database::connection();
        $stmt = $db->prepare(
            'UPDATE incidents SET
                peak_mbit_in = GREATEST(peak_mbit_in, :mbit),
                peak_pps_in = GREATEST(peak_pps_in, :pps),
                peak_total_conn = GREATEST(peak_total_conn, :conn),
                peak_syn_recv = GREATEST(peak_syn_recv, :syn)
             WHERE id = :id'
        );
        $stmt->execute([
            'mbit' => $metrics['mbit_in'],
            'pps' => $metrics['pps_in'],
            'conn' => $metrics['total_conn'],
            'syn' => $metrics['syn_recv'],
            'id' => $this->activeIncidentId,
        ]);
        $this->upsertSuspects($metrics);
    }

    private function resolveIncident(): void
    {
        $db = Database::connection();
        $db->prepare("UPDATE incidents SET status = 'resolved', resolved_at = NOW() WHERE id = :id")
            ->execute(['id' => $this->activeIncidentId]);

        $incident = $db->query('SELECT * FROM incidents WHERE id = ' . $this->activeIncidentId)->fetch();
        Notifier::notifyIncidentResolved($incident);
        $this->activeIncidentId = null;
    }

    /** Legt/aktualisiert die Top-Verdächtigen für den aktiven Vorfall an und liefert die Top 25. */
    private function upsertSuspects(array $metrics): array
    {
        $perIp = $metrics['per_ip'];
        uasort($perIp, static fn($a, $b) => $b['conn'] <=> $a['conn']);
        $top = array_slice($perIp, 0, 25, true);

        $db = Database::connection();
        $stmt = $db->prepare(
            'INSERT INTO suspects (incident_id, ip, conn_count, syn_recv_count, first_seen_at, last_seen_at, suggested_cmd_nft, suggested_cmd_iptables)
             VALUES (:incident_id, :ip, :conn, :syn, NOW(), NOW(), :nft, :ipt)
             ON DUPLICATE KEY UPDATE
                conn_count = VALUES(conn_count),
                syn_recv_count = VALUES(syn_recv_count),
                last_seen_at = NOW()'
        );
        $result = [];
        foreach ($top as $ip => $stat) {
            $nft = "nft add rule inet filter input ip saddr $ip drop";
            $ipt = "iptables -I INPUT -s $ip -j DROP";
            $stmt->execute([
                'incident_id' => $this->activeIncidentId,
                'ip' => $ip,
                'conn' => $stat['conn'],
                'syn' => $stat['syn'],
                'nft' => $nft,
                'ipt' => $ipt,
            ]);
            $result[] = ['ip' => $ip, 'conn_count' => $stat['conn'], 'syn_recv_count' => $stat['syn']];
        }
        return $result;
    }

    private function insertSample(array $metrics): void
    {
        $stmt = Database::connection()->prepare(
            'INSERT INTO samples (ts, mbit_in, pps_in, mbit_out, pps_out, total_conn, syn_recv, incident_id)
             VALUES (NOW(), :mbit_in, :pps_in, :mbit_out, :pps_out, :conn, :syn, :incident_id)'
        );
        $stmt->execute([
            'mbit_in' => $metrics['mbit_in'],
            'pps_in' => $metrics['pps_in'],
            'mbit_out' => $metrics['mbit_out'],
            'pps_out' => $metrics['pps_out'],
            'conn' => $metrics['total_conn'],
            'syn' => $metrics['syn_recv'],
            'incident_id' => $this->activeIncidentId,
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
