<?php

declare(strict_types=1);

namespace Vsrp\Ddos;

/**
 * Ermittelt das neueste Release des Desktop-Clients auf GitHub (Repository aus GITHUB_REPO in der .env),
 * mit kurzem Datei-Cache, damit GitHubs Abfragelimit nicht ausgeschöpft wird.
 */
final class Release
{
    private const CACHE_SECONDS = 300;

    /** @return array{tag:string,version:string,notes:string,published:string,url:string,asset_name:string,asset_url:string,asset_size:int}|null */
    public static function latest(): ?array
    {
        $repo = (string)Config::get('github_repo', '');
        if (!preg_match('#^[\w.\-]+/[\w.\-]+$#', $repo)) {
            return null;
        }

        $cache = sys_get_temp_dir() . '/vsrp_release_' . md5($repo) . '.json';
        if (is_file($cache) && time() - filemtime($cache) < self::CACHE_SECONDS) {
            $cached = json_decode((string)file_get_contents($cache), true);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $ch = curl_init('https://api.github.com/repos/' . $repo . '/releases/latest');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_HTTPHEADER => ['Accept: application/vnd.github+json', 'User-Agent: VSRP-DDoS-Monitor'],
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false || $code !== 200) {
            // Bei Fehlern lieber einen älteren Cache liefern als nichts
            if (is_file($cache)) {
                $old = json_decode((string)file_get_contents($cache), true);
                return is_array($old) ? $old : null;
            }
            return null;
        }

        $data = json_decode($body, true);
        if (!is_array($data)) {
            return null;
        }
        $asset = null;
        foreach ($data['assets'] ?? [] as $a) {
            if (isset($a['name']) && str_ends_with(strtolower($a['name']), '.msi')) {
                $asset = $a;
                break;
            }
        }
        if ($asset === null) {
            return null;
        }

        $result = [
            'tag' => (string)($data['tag_name'] ?? ''),
            'version' => ltrim((string)($data['tag_name'] ?? ''), 'vV'),
            'notes' => (string)($data['body'] ?? ''),
            'published' => (string)($data['published_at'] ?? ''),
            'url' => (string)($data['html_url'] ?? ''),
            'asset_name' => (string)$asset['name'],
            'asset_url' => (string)$asset['browser_download_url'],
            'asset_size' => (int)($asset['size'] ?? 0),
        ];
        @file_put_contents($cache, json_encode($result));
        return $result;
    }
}
