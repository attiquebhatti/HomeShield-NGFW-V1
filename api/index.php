<?php
/**
 * HomeShield NGFW - MySQL REST API
 * Deploy this file (and the api/ folder) to your Hostinger public_html/api/ directory.
 *
 * Environment variables required (set in Hostinger's Environment Variables panel):
 *   DB_HOST     - MySQL host (usually localhost or the internal hostname)
 *   DB_NAME     - Database name (e.g. u692327343_Shield_DB)
 *   DB_USER     - Database user (e.g. u692327343_Shield)
 *   DB_PASS     - Database password
 *   JWT_SECRET  - A long random secret string for signing tokens (generate one at random.org)
 *   ADMIN_EMAIL - Initial admin email address
 *   ADMIN_PASS  - Initial admin password (hashed with bcrypt on first run)
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ─── Config ────────────────────────────────────────────────────────────────

$dbHost = getenv('DB_HOST') ?: 'localhost';
$dbName = getenv('DB_NAME') ?: '';
$dbUser = getenv('DB_USER') ?: '';
$dbPass = getenv('DB_PASS') ?: '';
$jwtSecret = getenv('JWT_SECRET') ?: 'changeme_set_jwt_secret_env_var';

// ─── Database ──────────────────────────────────────────────────────────────

function getDb(): PDO {
    global $dbHost, $dbName, $dbUser, $dbPass;
    static $pdo = null;
    if ($pdo === null) {
        try {
            $pdo = new PDO(
                "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4",
                $dbUser,
                $dbPass,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
            );
        } catch (PDOException $e) {
            jsonError(503, 'Database connection failed: ' . $e->getMessage());
        }
    }
    return $pdo;
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function jsonResponse($data, int $code = 200): void {
    http_response_code($code);
    echo json_encode($data);
    exit();
}

function jsonError(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit();
}

function getBody(): array {
    $raw = file_get_contents('php://input');
    return $raw ? (json_decode($raw, true) ?? []) : [];
}

function uuid(): string {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

function now(): string {
    return date('Y-m-d H:i:s');
}

// Cast booleans from MySQL (returns "0"/"1" strings) to actual PHP bools
function castRow(array $row, array $boolFields = []): array {
    foreach ($boolFields as $field) {
        if (isset($row[$field])) {
            $row[$field] = (bool)(int)$row[$field];
        }
    }
    // Parse JSON fields
    foreach ($row as $k => $v) {
        if (is_string($v) && strlen($v) > 0 && ($v[0] === '{' || $v[0] === '[')) {
            $decoded = json_decode($v, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $row[$k] = $decoded;
            }
        }
    }
    return $row;
}

function castRows(array $rows, array $boolFields = []): array {
    return array_map(fn($r) => castRow($r, $boolFields), $rows);
}

// ─── JWT ───────────────────────────────────────────────────────────────────

function jwtEncode(array $payload): string {
    global $jwtSecret;
    $header = base64url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload['exp'] = time() + 86400 * 7; // 7-day token
    $body = base64url_encode(json_encode($payload));
    $sig = base64url_encode(hash_hmac('sha256', "$header.$body", $jwtSecret, true));
    return "$header.$body.$sig";
}

function jwtDecode(string $token): ?array {
    global $jwtSecret;
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    [$header, $body, $sig] = $parts;
    $expected = base64url_encode(hash_hmac('sha256', "$header.$body", $jwtSecret, true));
    if (!hash_equals($expected, $sig)) return null;
    $payload = json_decode(base64url_decode($body), true);
    if (!$payload || $payload['exp'] < time()) return null;
    return $payload;
}

function base64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode(string $data): string {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}

function requireAuth(): array {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/i', $header, $m)) {
        jsonError(401, 'Missing authorization token');
    }
    $payload = jwtDecode($m[1]);
    if (!$payload) jsonError(401, 'Invalid or expired token');
    return $payload;
}

// ─── Router ────────────────────────────────────────────────────────────────

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
// Strip /api prefix and leading slash
$path = preg_replace('#^.*?/api#', '', $uri);
$path = trim($path, '/');
$segments = $path ? explode('/', $path) : [];

$resource = $segments[0] ?? '';
$id = $segments[1] ?? null;

// ─── Auth routes (no JWT required) ────────────────────────────────────────

if ($resource === 'auth') {
    $action = $id ?? '';

    if ($action === 'login' && $method === 'POST') {
        $body = getBody();
        $email = trim($body['email'] ?? '');
        $password = $body['password'] ?? '';

        if (!$email || !$password) jsonError(400, 'Email and password required');

        $db = getDb();
        $stmt = $db->prepare('SELECT id, email, password_hash FROM admin_users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            jsonError(401, 'Invalid email or password');
        }

        $token = jwtEncode(['user_id' => $user['id'], 'email' => $user['email']]);
        jsonResponse(['token' => $token, 'user' => ['id' => $user['id'], 'email' => $user['email']]]);
    }

    if ($action === 'signup' && $method === 'POST') {
        $body = getBody();
        $email = trim($body['email'] ?? '');
        $password = $body['password'] ?? '';

        if (!$email || strlen($password) < 12) jsonError(400, 'Password must be at least 12 characters');

        $db = getDb();
        $check = $db->prepare('SELECT id FROM admin_users WHERE email = ? LIMIT 1');
        $check->execute([$email]);
        if ($check->fetch()) jsonError(409, 'An account already exists');

        $hash = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $db->prepare('INSERT INTO admin_users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)');
        $stmt->execute([uuid(), $email, $hash, now()]);

        jsonResponse(['message' => 'Account created. Please sign in.']);
    }

    if ($action === 'me' && $method === 'GET') {
        $payload = requireAuth();
        jsonResponse(['user' => ['id' => $payload['user_id'], 'email' => $payload['email']]]);
    }

    jsonError(404, 'Unknown auth endpoint');
}

// ─── Require JWT for all other routes ─────────────────────────────────────
requireAuth();

// ─── CRUD helper ──────────────────────────────────────────────────────────

function fetchAll(string $table, array $boolFields = [], array $opts = []): void {
    $db = getDb();
    $where = [];
    $params = [];
    $countOnly = false;

    // Filters from query string
    $allowedFilters = $opts['filters'] ?? [];
    foreach ($allowedFilters as $col) {
        if (isset($_GET[$col])) {
            $where[] = "`$col` = ?";
            $params[] = $_GET[$col];
        }
    }

    // Search
    if (!empty($_GET['search']) && !empty($opts['searchCols'])) {
        $subs = [];
        foreach ($opts['searchCols'] as $col) {
            $subs[] = "`$col` LIKE ?";
            $params[] = '%' . $_GET['search'] . '%';
        }
        $where[] = '(' . implode(' OR ', $subs) . ')';
    }

    $whereClause = $where ? ('WHERE ' . implode(' AND ', $where)) : '';
    $orderCol = $opts['order'] ?? 'id';
    $orderDir = (($opts['orderDir'] ?? 'asc') === 'desc') ? 'DESC' : 'ASC';
    $limit = isset($opts['limit']) ? (int)$opts['limit'] : null;

    // Pagination
    $page = max(0, (int)($_GET['page'] ?? 0));
    $pageSize = isset($_GET['page_size']) ? (int)$_GET['page_size'] : ($limit ?? 50);
    $offset = $page * $pageSize;

    // Count
    $countStmt = $db->prepare("SELECT COUNT(*) as cnt FROM `$table` $whereClause");
    $countStmt->execute($params);
    $total = (int)($countStmt->fetch()['cnt'] ?? 0);

    $limitClause = "LIMIT $pageSize OFFSET $offset";
    $stmt = $db->prepare("SELECT * FROM `$table` $whereClause ORDER BY `$orderCol` $orderDir $limitClause");
    $stmt->execute($params);
    $rows = castRows($stmt->fetchAll(), $boolFields);

    jsonResponse(['data' => $rows, 'count' => $total]);
}

function fetchOne(string $table, string $id, array $boolFields = []): void {
    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM `$table` WHERE id = ? LIMIT 1");
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    if (!$row) jsonError(404, 'Not found');
    jsonResponse(['data' => castRow($row, $boolFields)]);
}

function insertRow(string $table, array $allowed, array $boolFields = [], array $defaults = []): void {
    $body = getBody();
    $db = getDb();

    $data = array_merge($defaults, array_intersect_key($body, array_flip($allowed)));
    $data['id'] = $data['id'] ?? uuid();
    if (!isset($data['created_at'])) $data['created_at'] = now();

    // Encode JSON fields
    foreach ($data as $k => $v) {
        if (is_array($v) || is_object($v)) $data[$k] = json_encode($v);
        if (is_bool($v)) $data[$k] = $v ? 1 : 0;
    }

    $cols = implode(', ', array_map(fn($c) => "`$c`", array_keys($data)));
    $placeholders = implode(', ', array_fill(0, count($data), '?'));
    $stmt = $db->prepare("INSERT INTO `$table` ($cols) VALUES ($placeholders)");
    $stmt->execute(array_values($data));

    $newStmt = $db->prepare("SELECT * FROM `$table` WHERE id = ? LIMIT 1");
    $newStmt->execute([$data['id']]);
    jsonResponse(['data' => castRow($newStmt->fetch(), $boolFields)], 201);
}

function updateRow(string $table, string $id, array $allowed, array $boolFields = []): void {
    $body = getBody();
    $db = getDb();

    $data = array_intersect_key($body, array_flip($allowed));
    if (empty($data)) jsonError(400, 'No valid fields to update');

    if (in_array('updated_at', $allowed)) $data['updated_at'] = now();

    foreach ($data as $k => $v) {
        if (is_array($v) || is_object($v)) $data[$k] = json_encode($v);
        if (is_bool($v)) $data[$k] = $v ? 1 : 0;
    }

    $sets = implode(', ', array_map(fn($c) => "`$c` = ?", array_keys($data)));
    $stmt = $db->prepare("UPDATE `$table` SET $sets WHERE id = ?");
    $stmt->execute([...array_values($data), $id]);

    $newStmt = $db->prepare("SELECT * FROM `$table` WHERE id = ? LIMIT 1");
    $newStmt->execute([$id]);
    $row = $newStmt->fetch();
    if (!$row) jsonError(404, 'Not found');
    jsonResponse(['data' => castRow($row, $boolFields)]);
}

function deleteRow(string $table, string $id): void {
    $db = getDb();
    $stmt = $db->prepare("DELETE FROM `$table` WHERE id = ?");
    $stmt->execute([$id]);
    jsonResponse(['success' => true]);
}

// ─── Routes ────────────────────────────────────────────────────────────────

switch ($resource) {

    // ── Firewall Policies ────────────────────────────────────────────────
    case 'firewall-policies':
        $bools = ['enabled', 'log_enabled'];
        if ($method === 'GET' && !$id) {
            fetchAll('firewall_policies', $bools, [
                'order' => 'priority', 'orderDir' => 'asc', 'limit' => 500,
                'filters' => ['action', 'enabled'],
                'searchCols' => ['name', 'src_ip', 'dst_ip'],
            ]);
        } elseif ($method === 'GET' && $id) {
            fetchOne('firewall_policies', $id, $bools);
        } elseif ($method === 'POST' && !$id) {
            insertRow('firewall_policies', [
                'name', 'description', 'enabled', 'action', 'direction',
                'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                'interface', 'schedule', 'tags', 'priority', 'log_enabled',
            ], $bools, ['updated_at' => now()]);
        } elseif (($method === 'PUT' || $method === 'PATCH') && $id) {
            updateRow('firewall_policies', $id, [
                'name', 'description', 'enabled', 'action', 'direction',
                'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                'interface', 'schedule', 'tags', 'priority', 'log_enabled', 'updated_at',
            ], $bools);
        } elseif ($method === 'DELETE' && $id) {
            deleteRow('firewall_policies', $id);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── Firewall Logs ────────────────────────────────────────────────────
    case 'firewall-logs':
        if ($method === 'GET') {
            fetchAll('firewall_logs', [], [
                'order' => 'timestamp', 'orderDir' => 'desc',
                'filters' => ['action', 'protocol'],
                'searchCols' => ['src_ip', 'dst_ip', 'policy_name'],
            ]);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── DNS Entries ──────────────────────────────────────────────────────
    case 'dns-entries':
        $bools = ['enabled'];
        if ($method === 'GET' && !$id) {
            fetchAll('dns_entries', $bools, [
                'order' => 'created_at', 'orderDir' => 'desc',
                'filters' => ['list_type'],
                'searchCols' => ['domain'],
            ]);
        } elseif ($method === 'POST' && !$id) {
            insertRow('dns_entries', ['domain', 'list_type', 'category', 'source', 'enabled', 'note'], $bools);
        } elseif (($method === 'PUT' || $method === 'PATCH') && $id) {
            updateRow('dns_entries', $id, ['domain', 'list_type', 'category', 'source', 'enabled', 'note'], $bools);
        } elseif ($method === 'DELETE' && $id) {
            deleteRow('dns_entries', $id);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── DNS Logs ─────────────────────────────────────────────────────────
    case 'dns-logs':
        if ($method === 'GET') {
            fetchAll('dns_logs', [], [
                'order' => 'timestamp', 'orderDir' => 'desc',
                'filters' => ['action'],
                'searchCols' => ['domain', 'client_ip'],
            ]);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── IDS Alerts ───────────────────────────────────────────────────────
    case 'ids-alerts':
        $bools = ['acknowledged'];
        if ($method === 'GET' && !$id) {
            fetchAll('ids_alerts', $bools, [
                'order' => 'timestamp', 'orderDir' => 'desc',
                'filters' => ['severity', 'acknowledged'],
                'searchCols' => ['signature_name', 'src_ip', 'dst_ip'],
            ]);
        } elseif (($method === 'PUT' || $method === 'PATCH') && $id) {
            updateRow('ids_alerts', $id, ['acknowledged'], $bools);
        } elseif ($method === 'POST' && $id === 'acknowledge-many') {
            // Batch acknowledge: POST /api/ids-alerts/acknowledge-many  body: { ids: [...] }
            $body = getBody();
            $ids = $body['ids'] ?? [];
            if (empty($ids)) jsonError(400, 'ids array required');
            $db = getDb();
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $stmt = $db->prepare("UPDATE ids_alerts SET acknowledged = 1 WHERE id IN ($placeholders)");
            $stmt->execute($ids);
            jsonResponse(['updated' => $stmt->rowCount()]);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── Threat Feeds ─────────────────────────────────────────────────────
    case 'threat-feeds':
        $bools = ['enabled'];
        if ($method === 'GET' && !$id) {
            fetchAll('threat_feeds', $bools, ['order' => 'created_at', 'orderDir' => 'desc']);
        } elseif ($method === 'POST' && !$id) {
            insertRow('threat_feeds', ['name', 'description', 'url', 'feed_type', 'enabled', 'last_updated', 'last_status', 'indicator_count', 'refresh_interval_hours'], $bools);
        } elseif (($method === 'PUT' || $method === 'PATCH') && $id) {
            updateRow('threat_feeds', $id, ['name', 'description', 'url', 'feed_type', 'enabled', 'last_updated', 'last_status', 'indicator_count', 'refresh_interval_hours'], $bools);
        } elseif ($method === 'DELETE' && $id) {
            deleteRow('threat_feeds', $id);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── Network Interfaces ───────────────────────────────────────────────
    case 'network-interfaces':
        if ($method === 'GET' && !$id) {
            fetchAll('network_interfaces', [], ['order' => 'name', 'orderDir' => 'asc']);
        } elseif (($method === 'PUT' || $method === 'PATCH') && $id) {
            updateRow('network_interfaces', $id, ['display_name', 'role', 'ip_address', 'netmask', 'mtu', 'status', 'rx_bytes', 'tx_bytes', 'updated_at']);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── NAT Rules ────────────────────────────────────────────────────────
    case 'nat-rules':
        $bools = ['enabled'];
        if ($method === 'GET' && !$id) {
            fetchAll('nat_rules', $bools, ['order' => 'priority', 'orderDir' => 'asc']);
        } elseif ($method === 'POST' && !$id) {
            insertRow('nat_rules', ['name', 'description', 'enabled', 'nat_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'translate_to_ip', 'translate_to_port', 'interface', 'priority'], $bools, ['updated_at' => now()]);
        } elseif (($method === 'PUT' || $method === 'PATCH') && $id) {
            updateRow('nat_rules', $id, ['name', 'description', 'enabled', 'nat_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'translate_to_ip', 'translate_to_port', 'interface', 'priority', 'updated_at'], $bools);
        } elseif ($method === 'DELETE' && $id) {
            deleteRow('nat_rules', $id);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── System Settings ──────────────────────────────────────────────────
    case 'system-settings':
        if ($method === 'GET') {
            $db = getDb();
            $stmt = $db->query('SELECT * FROM system_settings');
            jsonResponse(['data' => $stmt->fetchAll()]);
        } elseif ($method === 'POST') {
            // Upsert: body is array of { key, value, description }
            $body = getBody();
            $items = $body['items'] ?? $body;
            if (!is_array($items)) jsonError(400, 'Expected array of settings');
            // Handle both array-of-objects and single object
            if (isset($items['key'])) $items = [$items];
            $db = getDb();
            foreach ($items as $item) {
                $key = $item['key'] ?? '';
                $value = $item['value'] ?? '';
                $desc = $item['description'] ?? '';
                if (!$key) continue;
                $stmt = $db->prepare('INSERT INTO system_settings (`key`, value, description, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value), description = VALUES(description), updated_at = VALUES(updated_at)');
                $stmt->execute([$key, $value, $desc, now()]);
            }
            $stmt2 = $db->query('SELECT * FROM system_settings');
            jsonResponse(['data' => $stmt2->fetchAll()]);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── Audit Log ────────────────────────────────────────────────────────
    case 'audit-log':
        if ($method === 'GET') {
            fetchAll('audit_log', [], [
                'order' => 'timestamp', 'orderDir' => 'desc',
                'searchCols' => ['actor', 'action', 'resource_type'],
            ]);
        } elseif ($method === 'POST') {
            insertRow('audit_log', ['actor', 'action', 'resource_type', 'resource_id', 'details', 'ip_address'], [], ['timestamp' => now()]);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── Sessions ─────────────────────────────────────────────────────────
    case 'sessions':
        if ($method === 'GET') {
            fetchAll('sessions', [], [
                'order' => 'last_seen', 'orderDir' => 'desc',
                'searchCols' => ['src_ip', 'dst_ip', 'application'],
            ]);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── Backup Records ───────────────────────────────────────────────────
    case 'backup-records':
        if ($method === 'GET') {
            fetchAll('backup_records', ['encrypted'], ['order' => 'created_at', 'orderDir' => 'desc']);
        } elseif ($method === 'POST' && !$id) {
            insertRow('backup_records', ['created_by', 'label', 'description', 'trigger_type', 'size_bytes', 'encrypted', 'payload', 'checksum'], ['encrypted']);
        } elseif ($method === 'DELETE' && $id) {
            deleteRow('backup_records', $id);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── Rule Apply History ───────────────────────────────────────────────
    case 'rule-apply-history':
        if ($method === 'GET') {
            fetchAll('rule_apply_history', [], ['order' => 'applied_at', 'orderDir' => 'desc']);
        } elseif ($method === 'POST' && !$id) {
            insertRow('rule_apply_history', ['applied_by', 'mode', 'os_target', 'rules_count', 'status', 'rollback_timer_seconds', 'compiled_output', 'rules_snapshot'], [], ['applied_at' => now()]);
        } elseif (($method === 'PUT' || $method === 'PATCH') && $id) {
            updateRow('rule_apply_history', $id, ['status', 'confirmed_at', 'rolled_back_at', 'error_message']);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    // ── System Health Snapshots ──────────────────────────────────────────
    case 'system-health':
        if ($method === 'GET') {
            fetchAll('system_health_snapshots', [], ['order' => 'recorded_at', 'orderDir' => 'desc']);
        } else {
            jsonError(405, 'Method not allowed');
        }
        break;

    default:
        jsonError(404, "Unknown resource: $resource");
}
