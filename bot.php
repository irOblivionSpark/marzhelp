<?php
// Function to display admin users with pagination
function displayAdmins($admins, $page = 1, $perPage = 10) {
    // Calculate total pages
    $totalAdmins = count($admins);
    $totalPages = ceil($totalAdmins / $perPage);

    // Get the starting admin index for the current page
    $start = ($page - 1) * $perPage;

    // Get the sliced array of admins for the current page
    $currentAdmins = array_slice($admins, $start, $perPage);

    // Display admins
    foreach ($currentAdmins as $admin) {
        echo '<div>' . htmlspecialchars($admin['name']) . '</div>'; // Assumes $admin has a 'name' attribute
    }

    // Display pagination controls
    echo '<div class="pagination">';
    for ($i = 1; $i <= $totalPages; $i++) {
        // Highlight the current page
        $active = ($i == $page) ? 'active' : '';
        echo '<a class="' . $active . '" href="?page=' . $i . '">' . $i . '</a> ';
    }
    echo '</div>';
}