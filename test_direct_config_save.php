<?php
/**
 * Direct Configuration Save Test
 * 
 * This script tests the configuration save mechanism without requiring aMember.
 * It simulates the configuration save process and tests well-known file generation.
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Simulate basic aMember classes and functions
class MockAmDi {
    private static $instance;
    public $config;
    public $hook;
    
    public static function getInstance() {
        if (!self::$instance) {
            self::$instance = new self();
            self::$instance->config = new MockConfig();
            self::$instance->hook = new MockHook();
        }
        return self::$instance;
    }
}

class MockConfig {
    private $data = [];
    
    public function get($key, $default = null) {
        return isset($this->data[$key]) ? $this->data[$key] : $default;
    }
    
    public function set($key, $value) {
        $this->data[$key] = $value;
        echo "CONFIG SET: $key = $value\n";
    }
    
    public function save() {
        echo "CONFIG SAVE CALLED\n";
        return true;
    }
    
    public function getData() {
        return $this->data;
    }
}

class MockHook {
    public function add($event, $callback) {
        echo "HOOK ADDED: $event\n";
    }
}

// Mock aMember functions
if (!class_exists('Am_Di')) {
    // Load the test class first so the mock classes are available
    require_once 'test_passkey_config_methods.php';
} else {
    require_once 'test_passkey_config_methods.php';
}

// Test configuration save
echo "=== Direct Configuration Save Test ===\n\n";

$plugin = new TestPasskeyConfig();

echo "1. Testing getRelatedOrigins() method:\n";
$origins = $plugin->testGetRelatedOrigins();
print_r($origins);
echo "\n";

echo "2. Testing addRelatedOrigin() method:\n";
$result = $plugin->testAddRelatedOrigin('kumpe3d.com');
print_r($result);
echo "\n";

echo "3. Testing configuration after add:\n";
$origins = $plugin->testGetRelatedOrigins();
print_r($origins);
echo "\n";

echo "4. Testing updateWellKnownFile() method:\n";
$fileResult = $plugin->testUpdateWellKnownFile();
echo "File update result: " . ($fileResult ? 'SUCCESS' : 'FAILED') . "\n\n";

echo "5. Checking if .well-known/webauthn file exists:\n";
$wellKnownFile = __DIR__ . '/.well-known/webauthn';
if (file_exists($wellKnownFile)) {
    echo "File exists! Content:\n";
    echo file_get_contents($wellKnownFile) . "\n";
} else {
    echo "File does not exist at: $wellKnownFile\n";
}
echo "\n";

echo "6. Testing removeRelatedOrigin() method:\n";
$result = $plugin->testRemoveRelatedOrigin('kumpe3d.com');
print_r($result);
echo "\n";

echo "7. Final configuration check:\n";
$origins = $plugin->testGetRelatedOrigins();
print_r($origins);
echo "\n";

echo "8. Testing configuration save hooks:\n";
$plugin->testOnConfigSave();
$plugin->testOnSetupFormsSave();
echo "\n";

echo "=== Test Complete ===\n";
?>
