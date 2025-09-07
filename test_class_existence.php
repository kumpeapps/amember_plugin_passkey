<?php

// Simulate aMember environment
define('AM_APPLICATION_PATH', '/tmp'); 

// Mock basic aMember classes that the plugin might depend on
if (!class_exists('Am_Plugin')) {
    class Am_Plugin {
        public function __construct($di, $config) {
            echo "Am_Plugin constructor called\n";
        }
    }
}

if (!class_exists('Am_Di')) {
    class Am_Di {
        public static function getInstance() {
            static $instance;
            if (!$instance) {
                $instance = new self();
            }
            return $instance;
        }
        
        public $hook;
        
        public function __construct() {
            $this->hook = new MockHook();
        }
    }
}

class MockHook {
    public function add($name, $callback) {
        echo "Hook registered: $name\n";
    }
}

echo "Loading passkey.php...\n";
require_once 'passkey.php';

echo "Checking if class exists...\n";
if (class_exists('Am_Plugin_Passkey')) {
    echo "✅ SUCCESS: Am_Plugin_Passkey class exists!\n";
    
    echo "Attempting to instantiate...\n";
    try {
        $plugin = new Am_Plugin_Passkey(null, null);
        echo "✅ SUCCESS: Plugin instantiated successfully!\n";
    } catch (Exception $e) {
        echo "❌ ERROR during instantiation: " . $e->getMessage() . "\n";
    }
} else {
    echo "❌ ERROR: Am_Plugin_Passkey class not found!\n";
}
