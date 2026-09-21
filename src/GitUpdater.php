<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

/**
 * Führt ausschließlich feste Git-Befehle (fetch/pull --ff-only, Statusabfragen) im App-Verzeichnis aus.
 * Es fließen keine Benutzereingaben in die Befehle ein.
 */
final class GitUpdater
{
    public static function root(): string
    {
        return dirname(__DIR__);
    }

    public static function available(): bool
    {
        return function_exists('proc_open')
            && is_dir(self::root() . '/.git')
            && self::gitBinary() !== null;
    }

    private static function gitBinary(): ?string
    {
        foreach (['/usr/bin/git', '/usr/local/bin/git', '/bin/git'] as $path) {
            if (is_executable($path)) {
                return $path;
            }
        }
        return null;
    }

    /** @return array{code:int,output:string} */
    public static function run(array $args, int $timeout = 60): array
    {
        $git = self::gitBinary();
        if ($git === null || !function_exists('proc_open')) {
            return ['code' => 127, 'output' => 'git oder proc_open ist auf diesem Server nicht verfügbar.'];
        }

        $cmd = array_merge([$git, '-C', self::root()], $args);
        $env = [
            'PATH' => '/usr/local/bin:/usr/bin:/bin',
            'HOME' => sys_get_temp_dir(),
            'GIT_TERMINAL_PROMPT' => '0',
            'LC_ALL' => 'C',
        ];
        $proc = @proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes, self::root(), $env);
        if (!is_resource($proc)) {
            return ['code' => 126, 'output' => 'Git konnte nicht gestartet werden (proc_open gesperrt?).'];
        }

        stream_set_blocking($pipes[1], false);
        $output = '';
        $exitCode = -1;
        $start = time();
        while (true) {
            $chunk = fread($pipes[1], 8192);
            if ($chunk !== false && $chunk !== '') {
                $output .= $chunk;
            }
            $status = proc_get_status($proc);
            if (!$status['running']) {
                $exitCode = (int)$status['exitcode'];
                $output .= (string)stream_get_contents($pipes[1]);
                break;
            }
            if (time() - $start > $timeout) {
                proc_terminate($proc);
                $output .= "\n[Abbruch: Zeitlimit von {$timeout}s überschritten]";
                $exitCode = 124;
                break;
            }
            usleep(100000);
        }
        fclose($pipes[1]);
        proc_close($proc);

        return ['code' => $exitCode, 'output' => trim($output)];
    }

    public static function currentCommit(): string
    {
        $r = self::run(['log', '-1', '--format=%h  %s  (%cd)', '--date=format:%d.%m.%Y %H:%M'], 10);
        return $r['code'] === 0 ? $r['output'] : 'unbekannt';
    }

    public static function branch(): string
    {
        $r = self::run(['rev-parse', '--abbrev-ref', 'HEAD'], 10);
        return $r['code'] === 0 ? $r['output'] : '?';
    }

    /** Holt den Remote-Stand und liefert die Anzahl neuer Commits (null bei Fehler) plus Liste der Änderungen bzw. Fehlertext. */
    public static function checkForUpdates(): array
    {
        $fetch = self::run(['fetch', '--quiet'], 60);
        if ($fetch['code'] !== 0) {
            return ['behind' => null, 'output' => $fetch['output']];
        }
        $count = self::run(['rev-list', '--count', 'HEAD..@{u}'], 10);
        $log = self::run(['log', '--format=%h  %s', 'HEAD..@{u}'], 10);
        return [
            'behind' => $count['code'] === 0 ? (int)$count['output'] : null,
            'output' => $count['code'] === 0 ? $log['output'] : $count['output'],
        ];
    }

    public static function pull(): array
    {
        $result = self::run(['pull', '--ff-only'], 90);
        if ($result['code'] === 0) {
            // Marker für den Collector-Dienst: er beendet sich danach und wird von systemd mit dem neuen Code neu gestartet
            @file_put_contents(self::root() . '/.update-stamp', (string)time());
        }
        return $result;
    }
}
