<?php
declare(strict_types=1);

date_default_timezone_set('Asia/Tehran');

require_once __DIR__ . '/../../config.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    $isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

    session_name('marzhelp_panel');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

function panelLogError(string $message): void
{
    file_put_contents(
        __DIR__ . '/../../logs.txt',
        date('Y-m-d H:i:s') . " - Panel: {$message}\n",
        FILE_APPEND
    );
}

function createConnection(string $host, string $user, string $pass, string $name, ?int $port = null): mysqli
{
    if ($port !== null) {
        $connection = new mysqli($host, $user, $pass, $name, $port);
    } else {
        $connection = new mysqli($host, $user, $pass, $name);
    }

    if ($connection->connect_error) {
        throw new RuntimeException("DB connection failed for {$name}: " . $connection->connect_error);
    }

    $connection->set_charset('utf8mb4');
    return $connection;
}

function openPanelConnections(): array
{
    global $botDbHost, $botDbUser, $botDbPass, $botDbName;
    global $vpnDbHost, $vpnDbUser, $vpnDbPass, $vpnDbName, $vpnDbPort;

    $botConn = null;

    try {
        $botConn = createConnection($botDbHost, $botDbUser, $botDbPass, $botDbName);

        $vpnPort = null;
        if (isset($vpnDbPort) && is_numeric((string) $vpnDbPort) && (int) $vpnDbPort > 0) {
            $vpnPort = (int) $vpnDbPort;
        }

        $marzbanConn = createConnection($vpnDbHost, $vpnDbUser, $vpnDbPass, $vpnDbName, $vpnPort);
        return [$botConn, $marzbanConn];
    } catch (Throwable $exception) {
        if ($botConn instanceof mysqli) {
            $botConn->close();
        }
        panelLogError($exception->getMessage());
        throw $exception;
    }
}

function closePanelConnections(mysqli $botConn, mysqli $marzbanConn): void
{
    $botConn->close();
    $marzbanConn->close();
}

function getCsrfToken(): string
{
    if (empty($_SESSION['panel_csrf_token'])) {
        $_SESSION['panel_csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['panel_csrf_token'];
}

function isValidCsrfToken(?string $token): bool
{
    if (!is_string($token) || $token === '' || empty($_SESSION['panel_csrf_token'])) {
        return false;
    }

    return hash_equals($_SESSION['panel_csrf_token'], $token);
}

function clearPanelSession(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'] ?? '',
            (bool) $params['secure'],
            (bool) $params['httponly']
        );
    }

    session_destroy();
}

function isPanelAuthenticated(): bool
{
    return isset($_SESSION['panel_admin']) && is_array($_SESSION['panel_admin']);
}

function getAuthenticatedAdmin(): ?array
{
    if (!isPanelAuthenticated()) {
        return null;
    }

    return $_SESSION['panel_admin'];
}

function verifyMarzbanPassword(string $plainPassword, string $hashedPassword): bool
{
    if ($hashedPassword === '') {
        return false;
    }

    if (password_verify($plainPassword, $hashedPassword)) {
        return true;
    }

    $cryptCheck = crypt($plainPassword, $hashedPassword);
    if (is_string($cryptCheck) && hash_equals($hashedPassword, $cryptCheck)) {
        return true;
    }

    if (strpos($hashedPassword, '$2b$') === 0) {
        $compatibleHash = '$2y$' . substr($hashedPassword, 4);
        $cryptCompatible = crypt($plainPassword, $compatibleHash);

        if (is_string($cryptCompatible) && hash_equals($compatibleHash, $cryptCompatible)) {
            return true;
        }
    }

    return false;
}

function verifyMarzbanPasswordViaApi(string $username, string $password): bool
{
    global $marzbanUrl;

    if (!isset($marzbanUrl) || trim((string) $marzbanUrl) === '') {
        return false;
    }

    $endpoint = rtrim((string) $marzbanUrl, '/') . '/api/admin/token';
    $postFields = http_build_query([
        'grant_type' => 'password',
        'username' => $username,
        'password' => $password,
        'scope' => '',
    ]);

    $ch = curl_init($endpoint);
    if ($ch === false) {
        panelLogError('Failed to initialize curl for Marzban API login.');
        return false;
    }

    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $postFields,
        CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 12,
    ]);

    $response = curl_exec($ch);
    if ($response === false) {
        panelLogError('Marzban API login cURL error: ' . curl_error($ch));
        curl_close($ch);
        return false;
    }

    $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($statusCode < 200 || $statusCode >= 300) {
        return false;
    }

    $payload = json_decode($response, true);
    return is_array($payload) && !empty($payload['access_token']);
}

function authenticatePanelAdmin(mysqli $marzbanConn, string $username, string $password): ?array
{
    $stmt = $marzbanConn->prepare(
        'SELECT id, username, hashed_password, is_sudo, telegram_id FROM admins WHERE username = ? LIMIT 1'
    );

    if (!$stmt) {
        panelLogError('Failed to prepare login query: ' . $marzbanConn->error);
        return null;
    }

    $stmt->bind_param('s', $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $admin = $result->fetch_assoc() ?: null;
    $stmt->close();

    if (!$admin) {
        return null;
    }

    $isValidPassword = verifyMarzbanPassword($password, (string) $admin['hashed_password']);
    if (!$isValidPassword) {
        $isValidPassword = verifyMarzbanPasswordViaApi($username, $password);
    }

    if (!$isValidPassword) {
        return null;
    }

    return [
        'id' => (int) $admin['id'],
        'username' => (string) $admin['username'],
        'is_sudo' => (int) ($admin['is_sudo'] ?? 0),
        'telegram_id' => $admin['telegram_id'] !== null ? (int) $admin['telegram_id'] : null,
    ];
}

function fetchAdminSettings(mysqli $botConn, int $adminId): array
{
    $stmt = $botConn->prepare(
        'SELECT total_traffic, expiry_date, status, user_limit, calculate_volume FROM admin_settings WHERE admin_id = ?'
    );

    if (!$stmt) {
        panelLogError('Failed to prepare settings query: ' . $botConn->error);
        return [
            'total_traffic' => null,
            'expiry_date' => null,
            'status' => null,
            'user_limit' => null,
            'calculate_volume' => 'used_traffic',
        ];
    }

    $stmt->bind_param('i', $adminId);
    $stmt->execute();
    $result = $stmt->get_result();
    $settings = $result->fetch_assoc() ?: [];
    $stmt->close();

    return [
        'total_traffic' => array_key_exists('total_traffic', $settings) ? (int) $settings['total_traffic'] : null,
        'expiry_date' => $settings['expiry_date'] ?? null,
        'status' => $settings['status'] ?? null,
        'user_limit' => array_key_exists('user_limit', $settings) ? (int) $settings['user_limit'] : null,
        'calculate_volume' => (string) ($settings['calculate_volume'] ?? 'used_traffic'),
    ];
}

function fetchUsedTrafficInGb(mysqli $marzbanConn, int $adminId, string $calculateVolume): float
{
    if ($calculateVolume === 'created_traffic') {
        $sql = "
            SELECT (
                IFNULL((SELECT SUM(CASE WHEN users.data_limit IS NOT NULL THEN users.data_limit ELSE users.used_traffic END)
                        FROM users WHERE users.admin_id = admins.id), 0) +
                IFNULL((SELECT SUM(user_usage_logs.used_traffic_at_reset)
                        FROM user_usage_logs
                        WHERE user_usage_logs.user_id IN (SELECT id FROM users WHERE users.admin_id = admins.id)), 0) +
                IFNULL((SELECT SUM(user_deletions.reseted_usage)
                        FROM user_deletions WHERE user_deletions.admin_id = admins.id), 0)
            ) / 1073741824 AS used_traffic_gb
            FROM admins
            WHERE admins.id = ?";
    } else {
        $sql = "
            SELECT (
                IFNULL((SELECT SUM(users.used_traffic)
                        FROM users WHERE users.admin_id = admins.id), 0) +
                IFNULL((SELECT SUM(user_usage_logs.used_traffic_at_reset)
                        FROM user_usage_logs
                        WHERE user_usage_logs.user_id IN (SELECT id FROM users WHERE users.admin_id = admins.id)), 0) +
                IFNULL((SELECT IFNULL(SUM(user_deletions.used_traffic), 0) + IFNULL(SUM(user_deletions.reseted_usage), 0)
                        FROM user_deletions WHERE user_deletions.admin_id = admins.id), 0)
            ) / 1073741824 AS used_traffic_gb
            FROM admins
            WHERE admins.id = ?";
    }

    $stmt = $marzbanConn->prepare($sql);
    if (!$stmt) {
        panelLogError('Failed to prepare traffic query: ' . $marzbanConn->error);
        return 0.0;
    }

    $stmt->bind_param('i', $adminId);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc() ?: [];
    $stmt->close();

    return round((float) ($row['used_traffic_gb'] ?? 0), 2);
}

function fetchUserStats(mysqli $marzbanConn, int $adminId): array
{
    $stmt = $marzbanConn->prepare(
        "SELECT
            COUNT(*) AS total_users,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_users,
            SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) AS expired_users,
            SUM(CASE WHEN TIMESTAMPDIFF(MINUTE, online_at, NOW()) <= 5 THEN 1 ELSE 0 END) AS online_users
        FROM users
        WHERE admin_id = ?"
    );

    if (!$stmt) {
        panelLogError('Failed to prepare user stats query: ' . $marzbanConn->error);
        return [
            'total_users' => 0,
            'active_users' => 0,
            'expired_users' => 0,
            'online_users' => 0,
        ];
    }

    $stmt->bind_param('i', $adminId);
    $stmt->execute();
    $result = $stmt->get_result();
    $stats = $result->fetch_assoc() ?: [];
    $stmt->close();

    return [
        'total_users' => (int) ($stats['total_users'] ?? 0),
        'active_users' => (int) ($stats['active_users'] ?? 0),
        'expired_users' => (int) ($stats['expired_users'] ?? 0),
        'online_users' => (int) ($stats['online_users'] ?? 0),
    ];
}

function parseAdminStatus(?string $statusJson): array
{
    $default = ['data' => 'active', 'time' => 'active', 'users' => 'active'];
    if ($statusJson === null || $statusJson === '') {
        return $default;
    }

    $decoded = json_decode($statusJson, true);
    if (!is_array($decoded)) {
        return $default;
    }

    return [
        'data' => (string) ($decoded['data'] ?? 'active'),
        'time' => (string) ($decoded['time'] ?? 'active'),
        'users' => (string) ($decoded['users'] ?? 'active'),
    ];
}

function calculateDaysLeft(?string $expiryDate): ?int
{
    if ($expiryDate === null || $expiryDate === '') {
        return null;
    }

    $expiryTimestamp = strtotime($expiryDate);
    if ($expiryTimestamp === false) {
        return null;
    }

    return (int) ceil(($expiryTimestamp - time()) / 86400);
}

function fetchAdminDashboardData(mysqli $botConn, mysqli $marzbanConn, int $adminId): ?array
{
    $stmt = $marzbanConn->prepare('SELECT id, username, is_sudo, telegram_id FROM admins WHERE id = ? LIMIT 1');
    if (!$stmt) {
        panelLogError('Failed to prepare admin profile query: ' . $marzbanConn->error);
        return null;
    }

    $stmt->bind_param('i', $adminId);
    $stmt->execute();
    $result = $stmt->get_result();
    $admin = $result->fetch_assoc() ?: null;
    $stmt->close();

    if (!$admin) {
        return null;
    }

    $settings = fetchAdminSettings($botConn, $adminId);
    $usedTrafficGb = fetchUsedTrafficInGb($marzbanConn, $adminId, $settings['calculate_volume']);
    $totalTrafficGb = null;
    if (is_int($settings['total_traffic']) && $settings['total_traffic'] > 0) {
        $totalTrafficGb = round($settings['total_traffic'] / 1073741824, 2);
    }

    $remainingTrafficGb = $totalTrafficGb === null ? null : round(max($totalTrafficGb - $usedTrafficGb, 0), 2);
    $daysLeft = calculateDaysLeft($settings['expiry_date']);

    $userStats = fetchUserStats($marzbanConn, $adminId);
    $userLimit = null;
    if (is_int($settings['user_limit']) && $settings['user_limit'] > 0) {
        $userLimit = $settings['user_limit'];
    }

    return [
        'admin' => [
            'id' => (int) $admin['id'],
            'username' => (string) $admin['username'],
            'is_sudo' => (int) ($admin['is_sudo'] ?? 0),
            'telegram_id' => $admin['telegram_id'] !== null ? (int) $admin['telegram_id'] : null,
        ],
        'usage' => [
            'calculate_volume' => $settings['calculate_volume'] === 'created_traffic' ? 'created_traffic' : 'used_traffic',
            'used_traffic_gb' => $usedTrafficGb,
            'total_traffic_gb' => $totalTrafficGb,
            'remaining_traffic_gb' => $remainingTrafficGb,
        ],
        'limits' => [
            'user_limit' => $userLimit,
            'remaining_user_limit' => $userLimit === null ? null : max($userLimit - $userStats['active_users'], 0),
            'expiry_date' => $settings['expiry_date'],
            'days_left' => $daysLeft,
        ],
        'status' => parseAdminStatus($settings['status']),
        'users' => $userStats,
    ];
}

function escapeHtml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function formatGb(?float $value): string
{
    if ($value === null) {
        return 'Unlimited';
    }

    return number_format($value, 2) . ' GB';
}
