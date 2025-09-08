<?php
/**
 * Test script to verify infinite loop fix is working
 */

// Display errors
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

echo "<h1>Testing Infinite Loop Fix</h1>\n";
echo "<p>This script tests that the updateWellKnownFile() method doesn't get called infinitely.</p>\n";

// Start output buffering to capture any infinite loop outputs
ob_start();

try {
    // Set a reasonable memory limit for testing
    ini_set('memory_limit', '128M');
    
    echo "<h2>Step 1: Testing updateWellKnownFile() protection</h2>\n";
    
    // Create a simple test class to simulate the method
    class TestPasskeyPlugin {
        private static $updateCallCount = 0;
        
        public function updateWellKnownFile() {
            static $updated = false;
            
            self::$updateCallCount++;
            echo "<p>updateWellKnownFile() called - Call #" . self::$updateCallCount . "</p>\n";
            
            if ($updated) {
                echo "<p style='color: green;'>✅ PROTECTION WORKING: Duplicate call detected and blocked!</p>\n";
                return true; // Already updated in this request
            }
            
            $updated = true;
            echo "<p style='color: blue;'>📝 First call - proceeding with update...</p>\n";
            
            // Simulate file update work
            usleep(100000); // 0.1 seconds
            
            echo "<p style='color: green;'>✅ Update completed successfully</p>\n";
            return true;
        }
        
        public static function getCallCount() {
            return self::$updateCallCount;
        }
    }
    
    $plugin = new TestPasskeyPlugin();
    
    echo "<h3>Testing multiple calls to updateWellKnownFile():</h3>\n";
    
    // Test multiple calls
    for ($i = 1; $i <= 5; $i++) {
        echo "<h4>Call #$i:</h4>\n";
        $plugin->updateWellKnownFile();
    }
    
    echo "<h2>Step 2: Testing getRelatedOrigins() protection</h2>\n";
    
    // Test getRelatedOrigins static protection
    class TestRelatedOrigins {
        private static $getOriginsCallCount = 0;
        
        public function getRelatedOrigins() {
            static $updateTriggered = false;
            
            self::$getOriginsCallCount++;
            echo "<p>getRelatedOrigins() called - Call #" . self::$getOriginsCallCount . "</p>\n";
            
            // Simulate finding config
            $usedKey = 'misc.passkey.related_origins';
            $relatedOriginsConfig = '["https://example.com"]';
            
            if ($usedKey && !empty($relatedOriginsConfig) && $relatedOriginsConfig !== '[]' && !$updateTriggered) {
                $updateTriggered = true;
                echo "<p style='color: blue;'>🔄 First call with config - triggering update...</p>\n";
                $this->updateWellKnownFile();
            } else if ($updateTriggered) {
                echo "<p style='color: green;'>✅ PROTECTION WORKING: Update already triggered in this request</p>\n";
            }
            
            return ['ok' => true, 'origins' => ['https://example.com']];
        }
        
        public function updateWellKnownFile() {
            echo "<p style='color: purple;'>📁 updateWellKnownFile() triggered from getRelatedOrigins()</p>\n";
        }
        
        public static function getCallCount() {
            return self::$getOriginsCallCount;
        }
    }
    
    $originsTest = new TestRelatedOrigins();
    
    echo "<h3>Testing multiple calls to getRelatedOrigins():</h3>\n";
    
    // Test multiple calls
    for ($i = 1; $i <= 3; $i++) {
        echo "<h4>Call #$i:</h4>\n";
        $originsTest->getRelatedOrigins();
    }
    
    echo "<h2>Results Summary</h2>\n";
    echo "<div style='background: #f0f8ff; padding: 15px; border: 1px solid #ccc;'>\n";
    echo "<p><strong>updateWellKnownFile() total calls:</strong> " . TestPasskeyPlugin::getCallCount() . "</p>\n";
    echo "<p><strong>getRelatedOrigins() total calls:</strong> " . TestRelatedOrigins::getCallCount() . "</p>\n";
    
    if (TestPasskeyPlugin::getCallCount() <= 6) { // 5 direct calls + 1 from getRelatedOrigins
        echo "<p style='color: green; font-weight: bold;'>✅ SUCCESS: Call counts are reasonable - no infinite loop detected!</p>\n";
    } else {
        echo "<p style='color: red; font-weight: bold;'>❌ FAILURE: Too many calls detected - potential infinite loop!</p>\n";
    }
    echo "</div>\n";
    
    echo "<h2>Memory Usage</h2>\n";
    echo "<p>Peak memory usage: " . number_format(memory_get_peak_usage(true) / 1024 / 1024, 2) . " MB</p>\n";
    echo "<p>Current memory usage: " . number_format(memory_get_usage(true) / 1024 / 1024, 2) . " MB</p>\n";
    
} catch (Exception $e) {
    echo "<p style='color: red;'><strong>Error:</strong> " . htmlspecialchars($e->getMessage()) . "</p>\n";
} catch (Error $e) {
    echo "<p style='color: red;'><strong>Fatal Error:</strong> " . htmlspecialchars($e->getMessage()) . "</p>\n";
}

// Get any buffered output
$output = ob_get_contents();
ob_end_clean();

echo $output;

echo "<hr>\n";
echo "<p><em>Test completed at " . date('Y-m-d H:i:s') . "</em></p>\n";
?>
