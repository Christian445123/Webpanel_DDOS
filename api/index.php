<?php

declare(strict_types=1);

require dirname(__DIR__) . '/autoload.php';

use Vsrp\Ddos\ApiAuth;
use Vsrp\Ddos\Database;
use Vsrp\Ddos\Detector;
use Vsrp\Ddos\License;

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

json_out(404, ['error' => 'not_found', 'message' => 'Unbekannte Route.']);
