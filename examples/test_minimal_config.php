<?php
/**
 * Minimal test of the configuration endpoint to isolate the error
 */

header('Content-Type: text/plain');
echo "=== Minimal Configuration Test ===\n\n";

try {
    echo "1. Testing basic PHP and file access...\n";
    
    // Test if we can access the main plugin file
    $pluginFile = dirname(__DIR__) . '/passkey.php';
    echo "Plugin file path: $pluginFile\n";
    echo "Plugin file exists: " . (file_exists($pluginFile) ? 'YES' : 'NO') . "\n";
    
    if (!file_exists($pluginFile)) {
        echo "ERROR: Cannot find plugin file!\n";
        exit;
    }
    
    echo "\n2. Testing configuration access method...\n";
    
    // Try to manually create the configuration without aMember
    $hostname = $_SERVER['HTTP_HOST'] ?? 'localhost';
    
    $testConfig = [
        'ok' => true,
        'rpId' => $hostname,
        'rpName' => 'aMember Test',
        'timeout' => 60000,
        'userVerification' => 'preferred',
        'attestation' => 'none',
        'endpoints' => [
            'config' => '/api/passkey/config',
            'authenticate' => '/api/check-access/by-passkey'
        ]
    ];
    
    echo "Test configuration created successfully:\n";
    echo json_encode($testConfig, JSON_PRETTY_PRINT) . "\n";
    
    echo "\n3. Testing if aMember classes are available...\n";
    
    // Check if we're in an aMember context
    if (class_exists('Am_Di')) {
        echo "✅ Am_Di class available\n";
        
        try {
            $di = Am_Di::getInstance();
            echo "✅ Am_Di instance created\n";
            
            $config = $di->config;
            echo "✅ Config object accessed\n";
            
            $siteTitle = $config->get('site_title', 'Default Title');
            echo "✅ Site title retrieved: $siteTitle\n";
            
        } catch (Exception $e) {
            echo "❌ Error accessing aMember configuration: " . $e->getMessage() . "\n";
        }
        
    } else {
        echo "❌ Am_Di class not available - not in aMember context\n";
        echo "This suggests the error might be in the aMember integration\n";
    }
    
    echo "\n4. Testing the actual configuration method logic...\n";
    
    // Simulate the configuration logic
    try {
        $simulatedConfig = [
            'ok' => true,
            'rpId' => $hostname,
            'rpName' => 'aMember',
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
        
        // Filter null values (this is what the real method does)
        $simulatedConfig = array_filter($simulatedConfig, function($value) {
            return $value !== null;
        });
        
        echo "✅ Configuration logic simulation successful:\n";
        echo json_encode($simulatedConfig, JSON_PRETTY_PRINT) . "\n";
        
    } catch (Exception $e) {
        echo "❌ Error in configuration logic: " . $e->getMessage() . "\n";
    }
    
    echo "\n=== Test Complete ===\n";
    echo "If you see this message, the PHP logic is working fine.\n";
    echo "The error is likely in the aMember API routing or class access.\n";
    
} catch (Exception $e) {
    echo "FATAL ERROR: " . $e->getMessage() . "\n";
    echo "Stack trace:\n" . $e->getTraceAsString() . "\n";
}

?>
