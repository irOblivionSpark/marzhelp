<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/bootstrap.php';

$errorMessage = '';
$dashboardData = null;
$botConn = null;
$marzbanConn = null;

try {
    [$botConn, $marzbanConn] = openPanelConnections();

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
        $csrfToken = $_POST['csrf_token'] ?? null;
        if (!isValidCsrfToken($csrfToken)) {
            $errorMessage = 'Invalid request token. Please refresh and try again.';
        } else {
            $username = trim((string) ($_POST['username'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');

            if ($username === '' || $password === '') {
                $errorMessage = 'Username and password are required.';
            } else {
                $authenticatedAdmin = authenticatePanelAdmin($marzbanConn, $username, $password);
                if ($authenticatedAdmin === null) {
                    $errorMessage = 'Invalid username or password.';
                } else {
                    session_regenerate_id(true);
                    $_SESSION['panel_admin'] = $authenticatedAdmin;
                    header('Location: index.php');
                    exit;
                }
            }
        }
    }

    $currentAdmin = getAuthenticatedAdmin();
    if ($currentAdmin !== null) {
        $dashboardData = fetchAdminDashboardData($botConn, $marzbanConn, (int) $currentAdmin['id']);
        if ($dashboardData === null) {
            clearPanelSession();
            header('Location: index.php');
            exit;
        }
    }
} catch (Throwable $exception) {
    panelLogError($exception->getMessage());
    $errorMessage = 'Panel is temporarily unavailable. Check database configuration.';
} finally {
    if ($botConn instanceof mysqli && $marzbanConn instanceof mysqli) {
        closePanelConnections($botConn, $marzbanConn);
    }
}

$isLoggedIn = $dashboardData !== null;
$csrfToken = getCsrfToken();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Marzhelp Panel</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<div class="bg-shape shape-1"></div>
<div class="bg-shape shape-2"></div>
<main class="container">
    <?php if (!$isLoggedIn): ?>
        <section class="card auth-card">
            <h1>Marzhelp Web Panel</h1>
            <p class="subtitle">Sign in with your Marzban admin username and password.</p>

            <?php if ($errorMessage !== ''): ?>
                <div class="alert error"><?= escapeHtml($errorMessage) ?></div>
            <?php endif; ?>

            <form method="post" autocomplete="off">
                <input type="hidden" name="action" value="login">
                <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">

                <label for="username">Username</label>
                <input id="username" name="username" type="text" required>

                <label for="password">Password</label>
                <input id="password" name="password" type="password" required>

                <button type="submit">Login</button>
            </form>
        </section>
    <?php else: ?>
        <?php
        $admin = $dashboardData['admin'];
        $usage = $dashboardData['usage'];
        $limits = $dashboardData['limits'];
        $users = $dashboardData['users'];
        $status = $dashboardData['status'];
        ?>
        <header class="panel-header">
            <div>
                <h1>Admin Dashboard</h1>
                <p class="subtitle">
                    <?= escapeHtml($admin['username']) ?> (ID: <?= (int) $admin['id'] ?>)
                    <?php if ((int) $admin['is_sudo'] === 1): ?>
                        <span class="badge">Sudo</span>
                    <?php endif; ?>
                </p>
            </div>
            <form method="post" action="logout.php">
                <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                <button type="submit" class="secondary">Logout</button>
            </form>
        </header>

        <?php if ($errorMessage !== ''): ?>
            <div class="alert error"><?= escapeHtml($errorMessage) ?></div>
        <?php endif; ?>

        <section class="grid">
            <article class="card metric">
                <h2>Used Traffic</h2>
                <p><?= escapeHtml(formatGb((float) $usage['used_traffic_gb'])) ?></p>
            </article>
            <article class="card metric">
                <h2>Total Traffic</h2>
                <p><?= escapeHtml(formatGb($usage['total_traffic_gb'])) ?></p>
            </article>
            <article class="card metric">
                <h2>Remaining Traffic</h2>
                <p><?= escapeHtml(formatGb($usage['remaining_traffic_gb'])) ?></p>
            </article>
            <article class="card metric">
                <h2>Volume Mode</h2>
                <p><?= $usage['calculate_volume'] === 'created_traffic' ? 'Created Traffic' : 'Used Traffic' ?></p>
            </article>
            <article class="card metric">
                <h2>Total Users</h2>
                <p><?= (int) $users['total_users'] ?></p>
            </article>
            <article class="card metric">
                <h2>Active Users</h2>
                <p><?= (int) $users['active_users'] ?></p>
            </article>
            <article class="card metric">
                <h2>Expired Users</h2>
                <p><?= (int) $users['expired_users'] ?></p>
            </article>
            <article class="card metric">
                <h2>Online Users</h2>
                <p><?= (int) $users['online_users'] ?></p>
            </article>
        </section>

        <section class="grid lower-grid">
            <article class="card details">
                <h2>Limits</h2>
                <ul>
                    <li>Expiry Date: <strong><?= $limits['expiry_date'] ? escapeHtml((string) $limits['expiry_date']) : 'Unlimited' ?></strong></li>
                    <li>Days Left: <strong><?= $limits['days_left'] === null ? 'Unlimited' : (int) $limits['days_left'] ?></strong></li>
                    <li>User Limit: <strong><?= $limits['user_limit'] === null ? 'Unlimited' : (int) $limits['user_limit'] ?></strong></li>
                    <li>Remaining User Slots: <strong><?= $limits['remaining_user_limit'] === null ? 'Unlimited' : (int) $limits['remaining_user_limit'] ?></strong></li>
                </ul>
            </article>

            <article class="card details">
                <h2>Status</h2>
                <div class="status-row">
                    <span>Time</span>
                    <span class="state <?= $status['time'] === 'active' ? 'ok' : 'warn' ?>">
                        <?= escapeHtml(ucfirst($status['time'])) ?>
                    </span>
                </div>
                <div class="status-row">
                    <span>Data</span>
                    <span class="state <?= $status['data'] === 'active' ? 'ok' : 'warn' ?>">
                        <?= escapeHtml(ucfirst($status['data'])) ?>
                    </span>
                </div>
                <div class="status-row">
                    <span>Users</span>
                    <span class="state <?= $status['users'] === 'active' ? 'ok' : 'warn' ?>">
                        <?= escapeHtml(ucfirst($status['users'])) ?>
                    </span>
                </div>
            </article>
        </section>
    <?php endif; ?>

    <footer class="panel-footer">
        Made with ❤️ by
        <a href="https://github.com/iroblivionSpark" target="_blank" rel="noopener noreferrer">OblivionSpark</a>
    </footer>
</main>
</body>
</html>
