<?php
// Debug script to test server-side logged-in detection
echo "<h2>Server-side Logged-in Detection Debug</h2>\n";

// Simulate the same logic as the plugin
$uri = $_SERVER['REQUEST_URI'] ?? '';
echo "<p><strong>Current URI:</strong> " . htmlspecialchars($uri) . "</p>\n";

// Session checks
echo "<h3>Session Variables:</h3>\n";
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
echo "<pre>";
foreach ($_SESSION as $key => $value) {
    if (strpos($key, 'admin') !== false || strpos($key, 'amember') !== false || strpos($key, 'user') !== false) {
        echo "$key: " . print_r($value, true) . "\n";
    }
}
echo "</pre>";

// Cookie checks
echo "<h3>Relevant Cookies:</h3>\n";
echo "<pre>";
foreach ($_COOKIE as $key => $value) {
    if (strpos($key, 'admin') !== false || strpos($key, 'amember') !== false || strpos($key, 'session') !== false) {
        echo "$key: " . htmlspecialchars($value) . "\n";
    }
}
echo "</pre>";

// GET parameters
echo "<h3>GET Parameters:</h3>\n";
echo "<pre>";
echo "module: " . ($_GET['module'] ?? 'not set') . "\n";
echo "controller: " . ($_GET['controller'] ?? 'not set') . "\n";
echo "_page: " . ($_GET['_page'] ?? 'not set') . "\n";
echo "</pre>";

// Replicate the exact logic from the plugin
$isLoggedIn = (
    // Session-based checks
    isset($_SESSION['_amember_user']) ||
    isset($_SESSION['amember_admin']) ||
    isset($_SESSION['admin_id']) ||
    // Cookie-based checks
    isset($_COOKIE['amember_admin']) ||
    isset($_COOKIE['admin_session']) ||
    // URL-based checks for logged-in admin areas (be more specific)
    strpos($uri, '/admin/dashboard') !== false ||
    strpos($uri, '/admin/members') !== false ||
    strpos($uri, '/admin/products') !== false ||
    strpos($uri, '/admin/setup') !== false ||
    strpos($uri, '/admin/users') !== false ||
    strpos($uri, '/admin/config') !== false ||
    strpos($uri, '/admin/reports') !== false ||
    strpos($uri, '/admin/payments') !== false ||
    // Parameter-based checks (these indicate you're inside admin interface)
    isset($_GET['module']) ||
    isset($_GET['controller']) ||
    isset($_GET['_page'])
);

// Special case: if URI is exactly '/admin' or '/admin?...' but not '/admin/something',
// this is likely the login page, so only use session/cookie checks, not URL patterns
if ($uri === '/admin' || (strpos($uri, '/admin?') === 0)) {
    $isLoggedIn = (
        isset($_SESSION['_amember_user']) ||
        isset($_SESSION['amember_admin']) ||
        isset($_SESSION['admin_id']) ||
        isset($_COOKIE['amember_admin']) ||
        isset($_COOKIE['admin_session'])
    );
}

echo "<h3>Final Decision:</h3>\n";
echo "<p><strong>Detected as logged in:</strong> " . ($isLoggedIn ? 'YES' : 'NO') . "</p>\n";
echo "<p><strong>Should inject passkey script:</strong> " . ($isLoggedIn ? 'NO' : 'YES') . "</p>\n";

// URL analysis
echo "<h3>URL Analysis:</h3>\n";
echo "<p>URI: " . htmlspecialchars($uri) . "</p>\n";
echo "<p>Is root admin (/admin): " . (($uri === '/admin' || (strpos($uri, '/admin?') === 0)) ? 'YES' : 'NO') . "</p>\n";
echo "<p>Has admin sub-path: " . ((strpos($uri, '/admin/') !== false) ? 'YES' : 'NO') . "</p>\n";
?>
