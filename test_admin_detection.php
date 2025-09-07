<?php
// Simple test for admin login page detection
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Simulate different admin URIs to test detection
$testUris = [
    '/admin',
    '/admin?login',
    '/admin/',
    '/admin/login',
    '/admin/dashboard',
    '/login',
    '/misc/passkey',
    '/admin-auth',
];

// Load the passkey plugin to get access to the class
require_once 'passkey.php';

echo "<h2>Admin Login Page Detection Test</h2>\n";

foreach ($testUris as $testUri) {
    echo "<h3>Testing URI: $testUri</h3>\n";
    
    // Set the REQUEST_URI for testing
    $_SERVER['REQUEST_URI'] = $testUri;
    
    try {
        // Create a minimal mock version for testing
        $testPlugin = new class {
            private function isAdminLoginPage()
            {
                $uri = $_SERVER['REQUEST_URI'];
                error_log("Passkey Plugin: isAdminLoginPage checking URI: " . $uri);
                
                // Same logic as in the main plugin
                $isAdminPage = (strpos($uri, '/admin') === 0 ||           // Starts with /admin
                    $uri === '/admin' ||                      // Exact /admin
                    strpos($uri, '/admin?') !== false ||      // /admin with query params
                    strpos($uri, 'admin-login') !== false ||  // Contains admin-login
                    strpos($uri, 'admin_login') !== false ||  // Contains admin_login
                    (strpos($uri, '/admin/') !== false &&     // /admin/ path but NOT dashboard/logged-in areas
                     strpos($uri, '/admin/dashboard') === false &&
                     strpos($uri, '/admin/members') === false &&
                     strpos($uri, '/admin/products') === false &&
                     strpos($uri, '/admin/setup') === false));
                
                // Exclude obvious logged-in admin areas and auth endpoints
                $isExcluded = (strpos($uri, 'admin-auth') !== false ||   // Auth endpoint
                    strpos($uri, '/logout') !== false ||      // Logout pages
                    strpos($uri, 'ajax') !== false);          // AJAX calls
                
                $result = $isAdminPage && !$isExcluded;
                error_log("Passkey Plugin: isAdminLoginPage result: " . ($result ? 'true' : 'false'));
                
                return $result;
            }
            
            public function testPageDetection() {
                return $this->isAdminLoginPage();
            }
        };
        
        $isAdminPage = $testPlugin->testPageDetection();
        
        echo "  - isAdminLoginPage(): " . ($isAdminPage ? '<strong style="color: green;">TRUE</strong>' : '<span style="color: red;">FALSE</span>') . "\n";
        echo "  - Would inject script: " . ($isAdminPage ? '<strong style="color: green;">YES</strong>' : '<span style="color: red;">NO</span>') . "\n";
        
    } catch (Exception $e) {
        echo "  - ERROR: " . $e->getMessage() . "\n";
    }
    
    echo "<br><br>\n";
}

echo "<h3>Debug Info</h3>\n";
echo "Current error_log setting: " . ini_get('error_log') . "<br>\n";
echo "Check your error logs for 'Passkey Plugin:' entries to see detailed debug output.<br>\n";
echo "You can also check with: <code>tail -f " . (ini_get('error_log') ?: '/var/log/php_errors.log') . " | grep 'Passkey Plugin'</code><br>\n";
?>
