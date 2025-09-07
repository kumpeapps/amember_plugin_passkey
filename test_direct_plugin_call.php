<?php
/**
 * Minimal API Test - Direct Plugin Method Call
 * This bypasses aMember's API routing to test the plugin methods directly
 */

// Include aMember bootstrap
require_once(__DIR__ . '/../../bootstrap.php');

error_log('Direct Plugin Test: Starting minimal API test');

try {
    // Get plugin instance
    $di = Am_Di::getInstance();
    $pluginManager = $di->plugins_misc;
    
    if (!$pluginManager) {
        error_log('Direct Plugin Test: Plugin manager not found');
        exit('Plugin manager not available');
    }
    
    $plugin = $pluginManager->get('passkey');
    if (!$plugin) {
        error_log('Direct Plugin Test: Passkey plugin not found');
        exit('Passkey plugin not loaded');
    }
    
    error_log('Direct Plugin Test: Plugin found, class: ' . get_class($plugin));
    
    // Create a mock request object
    $mockRequest = new stdClass();
    $mockRequest->method = 'GET';
    $mockRequest->path = '/api/passkey/config';
    
    error_log('Direct Plugin Test: Calling handlePasskeyConfig directly');
    
    // Call the method directly
    $result = $plugin->handlePasskeyConfig($mockRequest);
    
    error_log('Direct Plugin Test: Method returned: ' . json_encode($result));
    
    // Output result
    header('Content-Type: application/json');
    echo json_encode([
        'test' => 'direct_plugin_call',
        'success' => true,
        'result' => $result,
        'plugin_class' => get_class($plugin)
    ]);
    
} catch (Exception $e) {
    error_log('Direct Plugin Test: Exception: ' . $e->getMessage());
    error_log('Direct Plugin Test: Stack trace: ' . $e->getTraceAsString());
    
    header('Content-Type: application/json');
    echo json_encode([
        'test' => 'direct_plugin_call',
        'success' => false,
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);
}
?>
