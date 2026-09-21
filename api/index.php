<?php

declare(strict_types=1);

require dirname(__DIR__) . '/autoload.php';

use Vsrp\Ddos\ApiAuth;
use Vsrp\Ddos\Database;
use Vsrp\Ddos\Config;
use Vsrp\Ddos\Detector;
use Vsrp\Ddos\License;
use Vsrp\Ddos\Mail;
use Vsrp\Ddos\Models\Setting;

header('Content-Type: application/json; charset=utf-8');

function json_out(int $status, array $data): never
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

$route = trim((string)($_GET['r'] ?? ''), '/');
$segments = $route === '' ? [] : explode('/', $route);
$method = $_SERVER['REQUEST_METHOD'];

// POST /api/agent/report – Messwerte eines überwachten Servers (Authentifizierung mit dem Server-Schlüssel "vsrv_...")
if ($segments === ['agent', 'report'] && $method === 'POST') {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $token = preg_match('/^Bearer\s+(.+)$/i', $header, $m) ? trim($m[1]) : '';
    $stmt = Database::connection()->prepare('SELECT * FROM servers WHERE token_hash = :h AND revoked_at IS NULL LIMIT 1');
    $stmt->execute(['h' => ApiAuth::hash($token)]);
    $server = $token !== '' ? $stmt->fetch() : false;
    if (!$server) {
        json_out(401, ['error' => 'unauthorized', 'message' => 'Ungültiger Server-Schlüssel.']);
    }

    $body = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($body)) {
        json_out(422, ['error' => 'invalid_body']);
    }
    $num = static fn($v): float => is_numeric($v) ? max(0.0, (float)$v) : 0.0;
    $perIp = [];
    foreach (array_slice(is_array($body['per_ip'] ?? null) ? $body['per_ip'] : [], 0, 50, true) as $ip => $stat) {
        if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false && is_array($stat)) {
            $perIp[$ip] = ['conn' => (int)$num($stat['conn'] ?? 0), 'syn' => (int)$num($stat['syn'] ?? 0)];
        }
    }
    $metrics = [
        'mbit_in' => round($num($body['mbit_in'] ?? 0), 3),
        'pps_in' => (int)$num($body['pps_in'] ?? 0),
        'mbit_out' => round($num($body['mbit_out'] ?? 0), 3),
        'pps_out' => (int)$num($body['pps_out'] ?? 0),
        'total_conn' => (int)$num($body['total_conn'] ?? 0),
        'syn_recv' => (int)$num($body['syn_recv'] ?? 0),
        'per_ip' => $perIp,
    ];

    $state = json_decode((string)($server['state_json'] ?? ''), true);
    $state = Detector::evaluate($metrics, (int)$server['id'], is_array($state) ? $state : Detector::newState());

    $hostname = substr(preg_replace('/[^\w.\-]/', '', (string)($body['hostname'] ?? '')), 0, 255);
    Database::connection()->prepare(
        'UPDATE servers SET last_seen_at = NOW(), last_ip = :ip, hostname = :host, state_json = :st WHERE id = :id'
    )->execute(['ip' => $_SERVER['REMOTE_ADDR'] ?? null, 'host' => $hostname, 'st' => json_encode($state), 'id' => $server['id']]);

    json_out(200, ['ok' => true]);
}

$key = ApiAuth::authenticate();
if ($key === null) {
    json_out(401, ['error' => 'unauthorized', 'message' => 'Ungültiger oder fehlender API-Schlüssel.']);
}

$license = License::validate((string)($_SERVER['HTTP_X_LICENSE_KEY'] ?? ''));
if ($license === null) {
    json_out(403, ['error' => 'license_invalid', 'message' => 'Lizenzschlüssel fehlt, ist ungültig, widerrufen oder abgelaufen.']);
}

$db = Database::connection();

// GET /api/ping
if ($segments === ['ping'] && $method === 'GET') {
    json_out(200, [
        'ok' => true,
        'key_label' => $key['label'],
        'license_label' => $license['label'],
        'license_expires_at' => $license['expires_at'],
        'server_time' => date(DATE_ATOM),
    ]);
}

// GET /api/status
if ($segments === ['status'] && $method === 'GET') {
    $latest = $db->query('SELECT * FROM samples WHERE server_id IS NULL ORDER BY id DESC LIMIT 1')->fetch() ?: null;
    $active = $db->query("SELECT i.*, COALESCE(s.name, 'Hauptserver') AS server_name FROM incidents i LEFT JOIN servers s ON s.id = i.server_id WHERE i.status = 'active' ORDER BY i.id DESC LIMIT 1")->fetch() ?: null;
    json_out(200, ['latest_sample' => $latest, 'active_incident' => $active]);
}

// GET /api/samples?minutes=30
if ($segments === ['samples'] && $method === 'GET') {
    $minutes = max(1, min(1440, (int)($_GET['minutes'] ?? 30)));
    $stmt = $db->prepare('SELECT ts, mbit_in, pps_in, mbit_out, pps_out, total_conn, syn_recv FROM samples WHERE server_id IS NULL AND ts >= DATE_SUB(NOW(), INTERVAL :m MINUTE) ORDER BY id ASC');
    $stmt->execute(['m' => $minutes]);
    json_out(200, ['samples' => $stmt->fetchAll()]);
}

// GET /api/incidents?limit=50
if ($segments === ['incidents'] && $method === 'GET') {
    $limit = max(1, min(500, (int)($_GET['limit'] ?? 50)));
    $stmt = $db->prepare("SELECT i.*, COALESCE(s.name, 'Hauptserver') AS server_name FROM incidents i LEFT JOIN servers s ON s.id = i.server_id ORDER BY i.id DESC LIMIT " . $limit);
    $stmt->execute();
    json_out(200, ['incidents' => $stmt->fetchAll()]);
}

// GET /api/incidents/{id}
if (count($segments) === 2 && $segments[0] === 'incidents' && ctype_digit($segments[1]) && $method === 'GET') {
    $id = (int)$segments[1];
    $stmt = $db->prepare("SELECT i.*, COALESCE(s.name, 'Hauptserver') AS server_name FROM incidents i LEFT JOIN servers s ON s.id = i.server_id WHERE i.id = :id");
    $stmt->execute(['id' => $id]);
    $incident = $stmt->fetch();
    if (!$incident) {
        json_out(404, ['error' => 'not_found']);
    }
    $stmt = $db->prepare('SELECT * FROM suspects WHERE incident_id = :id ORDER BY conn_count DESC');
    $stmt->execute(['id' => $id]);
    json_out(200, ['incident' => $incident, 'suspects' => $stmt->fetchAll()]);
}

// POST /api/suspects/{id}/status  body: {"status":"manual_blocked|ignored|pending"}
if (count($segments) === 3 && $segments[0] === 'suspects' && ctype_digit($segments[1]) && $segments[2] === 'status' && $method === 'POST') {
    $id = (int)$segments[1];
    $body = json_decode(file_get_contents('php://input') ?: '{}', true) ?: [];
    $status = (string)($body['status'] ?? '');
    if (!in_array($status, ['manual_blocked', 'ignored', 'pending'], true)) {
        json_out(422, ['error' => 'invalid_status']);
    }
    $stmt = $db->prepare(
        'UPDATE suspects SET status = :s, status_updated_by = :by, status_updated_at = NOW() WHERE id = :id'
    );
    $stmt->execute(['s' => $status, 'by' => 'api:' . $key['label'], 'id' => $id]);
    if ($stmt->rowCount() === 0) {
        json_out(404, ['error' => 'not_found']);
    }
    json_out(200, ['ok' => true]);
}

// GET /api/servers – überwachte Server inkl. Status
if ($segments === ['servers'] && $method === 'GET') {
    $rows = $db->query(
        "SELECT s.id, s.name, s.hostname, s.token_hint, s.last_seen_at, s.last_ip, s.revoked_at, s.created_at,
                (SELECT COUNT(*) FROM incidents i WHERE i.server_id = s.id AND i.status = 'active') AS active_incidents,
                (SELECT mbit_in FROM samples x WHERE x.server_id = s.id ORDER BY x.id DESC LIMIT 1) AS last_mbit
         FROM servers s ORDER BY s.id DESC"
    )->fetchAll();
    foreach ($rows as &$r) {
        $seen = $r['last_seen_at'] ? strtotime($r['last_seen_at']) : null;
        $r['online'] = $seen !== null && time() - $seen < 90;
    }
    unset($r);
    json_out(200, ['servers' => $rows]);
}

// POST /api/servers  body: {"name":"..."} – legt einen Server an, der Schlüssel wird nur hier einmalig geliefert
if ($segments === ['servers'] && $method === 'POST') {
    $body = json_decode(file_get_contents('php://input') ?: '{}', true) ?: [];
    $name = substr(trim((string)($body['name'] ?? '')), 0, 100);
    if ($name === '') {
        json_out(422, ['error' => 'invalid_name', 'message' => 'Bitte einen Namen angeben.']);
    }
    $newKey = ApiAuth::newServerKey();
    $db->prepare('INSERT INTO servers (name, token_hash, token_hint) VALUES (:n, :h, :hint)')
        ->execute(['n' => $name, 'h' => ApiAuth::hash($newKey), 'hint' => substr($newKey, -4)]);
    $base = rtrim((string)Config::get('base_url', ''), '/');
    json_out(200, [
        'ok' => true,
        'name' => $name,
        'key' => $newKey,
        'install_command' => 'curl -fsSL ' . $base . '/agent/install.sh | sudo bash -s -- ' . $newKey,
    ]);
}

// POST /api/servers/{id}/revoke
if (count($segments) === 3 && $segments[0] === 'servers' && ctype_digit($segments[1]) && $segments[2] === 'revoke' && $method === 'POST') {
    $stmt = $db->prepare('UPDATE servers SET revoked_at = NOW() WHERE id = :id AND revoked_at IS NULL');
    $stmt->execute(['id' => (int)$segments[1]]);
    json_out($stmt->rowCount() > 0 ? 200 : 404, ['ok' => $stmt->rowCount() > 0]);
}

$thresholdKeys = [
    'mbit_threshold' => 'float', 'pps_threshold' => 'int', 'total_conn_threshold' => 'int', 'syn_recv_threshold' => 'int',
    'per_ip_conn_threshold' => 'int', 'sample_interval_seconds' => 'int', 'consecutive_to_trigger' => 'int',
    'consecutive_to_resolve' => 'int', 'monitor_interface' => 'string', 'samples_retention_days' => 'int',
];

// GET /api/settings – Schwellwerte + Status der Benachrichtigungen (Zugangsdaten selbst werden nie ausgeliefert)
if ($segments === ['settings'] && $method === 'GET') {
    $values = [];
    foreach ($thresholdKeys as $k => $type) {
        $values[$k] = Setting::get($k, '');
    }
    json_out(200, [
        'thresholds' => $values,
        'notifications' => [
            'smtp_host' => (string)Config::get('mail.host', ''),
            'from_email' => (string)Config::get('mail.from_email', ''),
            'alert_to' => (string)Config::get('mail.alert_to', ''),
            'discord_set' => (string)Config::get('discord_webhook_url', '') !== '',
        ],
    ]);
}

// POST /api/settings  body: {"thresholds":{...}}
if ($segments === ['settings'] && $method === 'POST') {
    $body = json_decode(file_get_contents('php://input') ?: '{}', true) ?: [];
    $in = is_array($body['thresholds'] ?? null) ? $body['thresholds'] : [];
    $save = [];
    foreach ($thresholdKeys as $k => $type) {
        if (!array_key_exists($k, $in)) {
            continue;
        }
        if ($type === 'string') {
            $v = trim((string)$in[$k]);
            if (!preg_match('/^[A-Za-z0-9_.:@-]{1,32}$/', $v)) {
                json_out(422, ['error' => 'invalid_value', 'message' => "Ungültiger Wert für $k."]);
            }
            $save[$k] = $v;
        } else {
            if (!is_numeric($in[$k]) || (float)$in[$k] <= 0) {
                json_out(422, ['error' => 'invalid_value', 'message' => "Ungültiger Wert für $k."]);
            }
            $save[$k] = $type === 'int' ? (string)(int)$in[$k] : (string)(float)$in[$k];
        }
    }
    if ($save) {
        Setting::setMany($save);
    }
    json_out(200, ['ok' => true]);
}

// POST /api/settings/test-email
if ($segments === ['settings', 'test-email'] && $method === 'POST') {
    $to = (string)Config::get('mail.alert_to', '');
    if ($to === '') {
        json_out(422, ['error' => 'no_recipient', 'message' => 'ALERT_EMAIL_TO ist in der .env nicht gesetzt.']);
    }
    $ok = Mail::send($to, 'Testmail – VSRP DDoS Monitor', "Das ist eine Testnachricht.\nWenn diese ankommt, sind die SMTP-Einstellungen korrekt.");
    json_out($ok ? 200 : 502, ['ok' => $ok, 'message' => $ok ? 'Test-E-Mail verschickt an ' . $to : 'Versand fehlgeschlagen. SMTP-Einstellungen prüfen.']);
}

json_out(404, ['error' => 'not_found', 'message' => 'Unbekannte Route.']);
