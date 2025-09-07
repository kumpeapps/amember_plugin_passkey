<?php
/**
 * Test the plugin directly to see the actual error
 * This file should be accessed via your aMember URL to get the proper context
 */

header('Content-Type: text/plain');
echo "=== Direct Plugin Test ===\n\n";

try {
    echo "1. Checking aMember environment...\n";
    
    if (!class_exists('Am_Di')) {
        echo "❌ Am_Di not available - this script must be run from aMember context\n";
        echo "Try accessing this via: https://www.kumpeapps.com/examples/test_plugin_direct.php\n";
        exit;
    }
    
    echo "✅ Am_Di available\n";
    
    $di = Am_Di::getInstance();
    echo "✅ Am_Di instance created\n";
    
    echo "\n2. Testing configuration access...\n";
    
    $config = $di->config;
    $hostname = $_SERVER['HTTP_HOST'];
    
    echo "Hostname: $hostname\n";
    echo "Site title: " . $config->get('site_title', 'Default') . "\n";
    
    echo "\n3. Simulating handlePasskeyConfig method...\n";
    
    // This is exactly what our method does
    $passkeyConfig = [
        'ok' => true,
        'rpId' => $hostname,
        'rpName' => $config->get('site_title', 'aMember'),
        'timeout' => 60000,
        'userVerification' => 'preferred',
        'authenticatorAttachment' => null,
        'requireResidentKey' => false,
        'attestation' => 'none',
        'endpoints' => [
            'config' => '/api/passkey/config',
            'authenticate' => '/api/check-access/by-passkey'
        ]
    ];
    
    echo "Configuration before filtering:\n";
    echo json_encode($passkeyConfig, JSON_PRETTY_PRINT) . "\n";
    
    // Filter null values
    $passkeyConfig = array_filter($passkeyConfig, function($value) {
        return $value !== null;
    });
    
    echo "\nConfiguration after filtering:\n";
    echo json_encode($passkeyConfig, JSON_PRETTY_PRINT) . "\n";
    
    echo "\n4. Testing plugin configuration access...\n";
    
    // Try to access plugin-specific config
    try {
        $pluginConfig = $config->get('misc.passkey');
        if ($pluginConfig) {
            echo "✅ Plugin configuration found:\n";
            echo json_encode($pluginConfig, JSON_PRETTY_PRINT) . "\n";
        } else {
            echo "ℹ️ No plugin-specific configuration found (using defaults)\n";
        }
    } catch (Exception $configException) {
        echo "⚠️ Plugin config access failed: " . $configException->getMessage() . "\n";
    }
    
    echo "\n=== SUCCESS ===\n";
    echo "The configuration logic works fine!\n";
    echo "If this works but the API endpoint fails, the issue is in the API routing.\n";
    
} catch (Exception $e) {
    echo "❌ ERROR: " . $e->getMessage() . "\n";
    echo "File: " . $e->getFile() . "\n";
    echo "Line: " . $e->getLine() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}

?>
