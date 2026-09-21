<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/autoload.php';

use Vsrp\Ddos\ApiAuth;
use Vsrp\Ddos\Database;

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

$key = ApiAuth::authenticate();
if ($key === null) {
    json_out(401, ['error' => 'unauthorized', 'message' => 'Ungültiger oder fehlender API-Schlüssel.']);
}

$db = Database::connection();

// GET /api/ping
if ($segments === ['ping'] && $method === 'GET') {
    json_out(200, ['ok' => true, 'key_label' => $key['label'], 'server_time' => date(DATE_ATOM)]);
}

// GET /api/status
if ($segments === ['status'] && $method === 'GET') {
    $latest = $db->query('SELECT * FROM samples ORDER BY id DESC LIMIT 1')->fetch() ?: null;
    $active = $db->query("SELECT * FROM incidents WHERE status = 'active' ORDER BY id DESC LIMIT 1")->fetch() ?: null;
    json_out(200, ['latest_sample' => $latest, 'active_incident' => $active]);
}

// GET /api/samples?minutes=30
if ($segments === ['samples'] && $method === 'GET') {
    $minutes = max(1, min(1440, (int)($_GET['minutes'] ?? 30)));
    $stmt = $db->prepare('SELECT ts, mbit_in, pps_in, mbit_out, pps_out, total_conn, syn_recv FROM samples WHERE ts >= DATE_SUB(NOW(), INTERVAL :m MINUTE) ORDER BY id ASC');
    $stmt->execute(['m' => $minutes]);
    json_out(200, ['samples' => $stmt->fetchAll()]);
}

// GET /api/incidents?limit=50
if ($segments === ['incidents'] && $method === 'GET') {
    $limit = max(1, min(500, (int)($_GET['limit'] ?? 50)));
    $stmt = $db->prepare('SELECT * FROM incidents ORDER BY id DESC LIMIT ' . $limit);
    $stmt->execute();
    json_out(200, ['incidents' => $stmt->fetchAll()]);
}

// GET /api/incidents/{id}
if (count($segments) === 2 && $segments[0] === 'incidents' && ctype_digit($segments[1]) && $method === 'GET') {
    $id = (int)$segments[1];
    $stmt = $db->prepare('SELECT * FROM incidents WHERE id = :id');
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
