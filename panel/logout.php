<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = $_POST['csrf_token'] ?? null;
    if (isValidCsrfToken($csrfToken)) {
        clearPanelSession();
        header('Location: index.php');
        exit;
    }
}

header('Location: index.php');
exit;
