<?php
/**
 * Simple test to check if the passkey plugin configuration endpoint works
 */

// This script helps diagnose the internal error in the configuration endpoint

require_once __DIR__ . '/../passkey.php';

// Create a mock request to test the configuration handler
class MockRequest {
    public function getParam($name) { return null; }
    public function getHeader($name) { return null; }
    public function getRawBody() { return '{}'; }
    public function getPost() { return []; }
    public function getPathInfo() { return '/api/passkey/config'; }
}

try {
    echo "Testing Passkey Plugin Configuration Handler...\n\n";
    
    // Create plugin instance
    $plugin = new Am_Plugin_Passkey(null, 'passkey', 'misc');
    
    echo "Plugin instance created successfully.\n";
    
    // Test the configuration handler directly
    $mockRequest = new MockRequest();
    
    echo "Calling handlePasskeyConfig...\n";
    
    // Use reflection to access the protected method
    $reflection = new ReflectionClass($plugin);
    $method = $reflection->getMethod('handlePasskeyConfig');
    $method->setAccessible(true);
    
    $result = $method->invoke($plugin, $mockRequest);
    
    echo "Configuration result:\n";
    echo json_encode($result, JSON_PRETTY_PRINT) . "\n";
    
    if (isset($result['ok']) && $result['ok']) {
        echo "\n✅ Configuration endpoint is working!\n";
    } else {
        echo "\n❌ Configuration endpoint has issues.\n";
        if (isset($result['error'])) {
            echo "Error: " . $result['error'] . "\n";
        }
    }
    
} catch (Exception $e) {
    echo "❌ Error testing configuration: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}
?>
