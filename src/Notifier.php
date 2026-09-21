<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

/**
 * Verschickt Alarm- und Entwarnungs-Benachrichtigungen über alle konfigurierten Kanäle (E-Mail, Discord).
 */
final class Notifier
{
    public static function notifyIncidentStarted(array $incident, array $suspects): void
    {
        $dashboardUrl = rtrim(Config::get('base_url', ''), '/');
        $link = $dashboardUrl !== '' ? $dashboardUrl . '/incident.php?id=' . $incident['id'] : '';

        $lines = [];
        $lines[] = 'Möglicher DDoS-Angriff erkannt (Vorfall #' . $incident['id'] . ')';
        $lines[] = 'Beginn: ' . $incident['started_at'];
        $lines[] = 'Auslöser: ' . $incident['trigger_reason'];
        $lines[] = '';
        $lines[] = sprintf(
            'Eingehend: %.1f MBit/s, %s Pakete/s, %s aktive Verbindungen, %s SYN-RECV',
            (float)$incident['peak_mbit_in'],
            number_format((float)$incident['peak_pps_in'], 0, ',', '.'),
            number_format((float)$incident['peak_total_conn'], 0, ',', '.'),
            number_format((float)$incident['peak_syn_recv'], 0, ',', '.')
        );
        $lines[] = '';
        if ($suspects) {
            $lines[] = 'Auffällige externe IP-Adressen (Top ' . count($suspects) . '):';
            foreach ($suspects as $s) {
                $lines[] = sprintf('  %s  –  %d Verbindungen (%d SYN-RECV)', $s['ip'], $s['conn_count'], $s['syn_recv_count']);
            }
            $lines[] = '';
            $lines[] = 'Vorgeschlagene Blockierbefehle stehen im Dashboard bereit (werden NICHT automatisch ausgeführt).';
        }
        if ($link !== '') {
            $lines[] = '';
            $lines[] = 'Details: ' . $link;
        }
        $body = implode("\n", $lines);

        $emailTo = (string)Config::get('mail.alert_to', '');
        $emailSent = false;
        if ($emailTo !== '') {
            $emailSent = Mail::send($emailTo, '⚠️ DDoS-Verdacht erkannt – Vorfall #' . $incident['id'], $body);
        }

        $fields = [];
        foreach (array_slice($suspects, 0, 15) as $s) {
            $fields[] = [$s['ip'], $s['conn_count'] . ' Verbindungen, ' . $s['syn_recv_count'] . ' SYN-RECV', true];
        }
        $discordSent = DiscordNotifier::send(
            '⚠️ DDoS-Verdacht erkannt – Vorfall #' . $incident['id'],
            sprintf(
                "**%.1f MBit/s** eingehend, **%s** Pakete/s, **%s** Verbindungen, **%s** SYN-RECV\n%s%s",
                (float)$incident['peak_mbit_in'],
                number_format((float)$incident['peak_pps_in'], 0, ',', '.'),
                number_format((float)$incident['peak_total_conn'], 0, ',', '.'),
                number_format((float)$incident['peak_syn_recv'], 0, ',', '.'),
                'Auslöser: ' . $incident['trigger_reason'],
                $link !== '' ? "\n[Dashboard öffnen]($link)" : ''
            ),
            $fields,
            0xE74C3C
        );

        Database::connection()->prepare(
            'UPDATE incidents SET notified_email = :e, notified_discord = :d WHERE id = :id'
        )->execute(['e' => $emailSent ? 1 : 0, 'd' => $discordSent ? 1 : 0, 'id' => $incident['id']]);
    }

    public static function notifyIncidentResolved(array $incident): void
    {
        $started = new \DateTimeImmutable($incident['started_at']);
        $resolved = new \DateTimeImmutable($incident['resolved_at']);
        $duration = $started->diff($resolved);
        $durationText = ($duration->days > 0 ? $duration->days . ' Tag(e), ' : '')
            . sprintf('%02d:%02d:%02d', $duration->h, $duration->i, $duration->s);

        $dashboardUrl = rtrim(Config::get('base_url', ''), '/');
        $link = $dashboardUrl !== '' ? $dashboardUrl . '/incident.php?id=' . $incident['id'] : '';

        $body = implode("\n", array_filter([
            'Entwarnung: Vorfall #' . $incident['id'] . ' ist beendet.',
            'Dauer: ' . $durationText,
            sprintf(
                'Spitzenwerte: %.1f MBit/s, %s Pakete/s, %s Verbindungen, %s SYN-RECV',
                (float)$incident['peak_mbit_in'],
                number_format((float)$incident['peak_pps_in'], 0, ',', '.'),
                number_format((float)$incident['peak_total_conn'], 0, ',', '.'),
                number_format((float)$incident['peak_syn_recv'], 0, ',', '.')
            ),
            $link !== '' ? 'Details: ' . $link : null,
        ]));

        $emailTo = (string)Config::get('mail.alert_to', '');
        if ($emailTo !== '') {
            Mail::send($emailTo, '✅ DDoS-Vorfall beendet – #' . $incident['id'], $body);
        }
        DiscordNotifier::send(
            '✅ DDoS-Vorfall beendet – #' . $incident['id'],
            "Dauer: **$durationText**" . ($link !== '' ? "\n[Dashboard öffnen]($link)" : ''),
            [],
            0x2ECC71
        );

        Database::connection()->prepare('UPDATE incidents SET resolved_notified = 1 WHERE id = :id')
            ->execute(['id' => $incident['id']]);
    }
}
