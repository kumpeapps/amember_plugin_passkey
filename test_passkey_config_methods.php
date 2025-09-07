<?php
/**
 * Test Passkey Configuration Methods
 * 
 * This class extracts only the configuration-related methods from the main plugin
 * for standalone testing without requiring aMember.
 */

// Mock aMember classes if not available
if (!class_exists('Am_Di')) {
    class Am_Di {
        private static $instance;
        public $config;
        public $hook;
        
        public static function getInstance() {
            if (!self::$instance) {
                self::$instance = new self();
                self::$instance->config = new Am_Config();
                self::$instance->hook = new Am_Hook();
            }
            return self::$instance;
        }
    }
    
    class Am_Config {
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
    }
    
    class Am_Hook {
        public function add($event, $callback) {
            echo "HOOK ADDED: $event\n";
        }
    }
}

class TestPasskeyConfig {
    
    /**
     * Test the getRelatedOrigins method
     */
    public function testGetRelatedOrigins() {
        try {
            $config = Am_Di::getInstance()->config;
            $currentHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
            
            // Try multiple possible config key locations
            $possibleKeys = [
                'misc.passkey.related_origins',
                'passkey.related_origins', 
                'related_origins',
                'misc.passkey.passkey.related_origins'
            ];
            
            $relatedOriginsConfig = '[]';
            $usedKey = null;
            
            foreach ($possibleKeys as $key) {
                $value = $config->get($key, null);
                if ($value !== null) {
                    $relatedOriginsConfig = $value;
                    $usedKey = $key;
                    break;
                }
            }
            
            echo "Related origins config key used: " . ($usedKey ?: 'none found') . ", value: " . $relatedOriginsConfig . "\n";
            
            $relatedOrigins = json_decode($relatedOriginsConfig, true);
            
            if (!is_array($relatedOrigins)) {
                $relatedOrigins = [];
            }
            
            // Normalize origins to ensure they have https:// prefix
            $normalizedOrigins = [];
            foreach ($relatedOrigins as $origin) {
                $origin = trim($origin);
                if (empty($origin)) {
                    continue;
                }
                
                // Add https:// if not present
                if (!preg_match('/^https?:\/\//', $origin)) {
                    $origin = 'https://' . $origin;
                }
                
                $normalizedOrigins[] = $origin;
            }
            
            // Always include the current host as the primary RP ID
            $origins = array_unique(array_merge(['https://' . $currentHost], $normalizedOrigins));
            
            return [
                'ok' => true,
                'rpId' => $currentHost,
                'origins' => $origins,
                'wellKnownUrl' => 'https://' . $currentHost . '/.well-known/webauthn',
                'configKey' => $usedKey,
                'rawConfig' => $relatedOriginsConfig
            ];
            
        } catch (Exception $e) {
            echo "Error getting related origins: " . $e->getMessage() . "\n";
            return [
                'ok' => false,
                'error' => 'Failed to get related origins: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Test adding a related origin
     */
    public function testAddRelatedOrigin($origin) {
        try {
            // Validate origin format
            if (!$this->testIsValidOrigin($origin)) {
                return ['ok' => false, 'error' => 'Invalid origin format. Use https://domain.com'];
            }
            
            // Add https:// if not present
            if (!preg_match('/^https?:\/\//', $origin)) {
                $origin = 'https://' . $origin;
            }
            
            $config = Am_Di::getInstance()->config;
            $relatedOriginsConfig = $config->get('misc.passkey.related_origins', '[]');
            $relatedOrigins = json_decode($relatedOriginsConfig, true);
            
            if (!is_array($relatedOrigins)) {
                $relatedOrigins = [];
            }
            
            // Add new origin if not already present
            if (!in_array($origin, $relatedOrigins)) {
                $relatedOrigins[] = $origin;
                
                // Save back to config
                $config->set('misc.passkey.related_origins', json_encode($relatedOrigins));
                $config->save();
                
                echo "Added related origin: " . $origin . "\n";
                return [
                    'ok' => true,
                    'message' => 'Related origin added successfully',
                    'origin' => $origin,
                    'total_origins' => count($relatedOrigins) + 1 // +1 for primary domain
                ];
            } else {
                return [
                    'ok' => true,
                    'message' => 'Origin already exists',
                    'origin' => $origin
                ];
            }
            
        } catch (Exception $e) {
            echo "Error adding related origin: " . $e->getMessage() . "\n";
            return [
                'ok' => false,
                'error' => 'Failed to add related origin: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Test removing a related origin
     */
    public function testRemoveRelatedOrigin($origin) {
        try {
            // Add https:// if not present
            if (!preg_match('/^https?:\/\//', $origin)) {
                $origin = 'https://' . $origin;
            }
            
            $config = Am_Di::getInstance()->config;
            $relatedOriginsConfig = $config->get('misc.passkey.related_origins', '[]');
            $relatedOrigins = json_decode($relatedOriginsConfig, true);
            
            if (!is_array($relatedOrigins)) {
                $relatedOrigins = [];
            }
            
            // Remove origin if present
            $key = array_search($origin, $relatedOrigins);
            if ($key !== false) {
                unset($relatedOrigins[$key]);
                $relatedOrigins = array_values($relatedOrigins); // Re-index array
                
                // Save back to config
                $config->set('misc.passkey.related_origins', json_encode($relatedOrigins));
                $config->save();
                
                echo "Removed related origin: " . $origin . "\n";
                return [
                    'ok' => true,
                    'message' => 'Related origin removed successfully',
                    'origin' => $origin,
                    'total_origins' => count($relatedOrigins) + 1 // +1 for primary domain
                ];
            } else {
                return [
                    'ok' => false,
                    'error' => 'Origin not found in related origins list',
                    'origin' => $origin
                ];
            }
            
        } catch (Exception $e) {
            echo "Error removing related origin: " . $e->getMessage() . "\n";
            return [
                'ok' => false,
                'error' => 'Failed to remove related origin: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Test the updateWellKnownFile method
     */
    public function testUpdateWellKnownFile() {
        try {
            // Get document root
            $documentRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
            if (empty($documentRoot)) {
                echo "Cannot update .well-known file - document root not available\n";
                return false;
            }
            
            $wellKnownDir = $documentRoot . '/.well-known';
            $wellKnownFile = $wellKnownDir . '/webauthn';
            
            echo "Well-known directory: $wellKnownDir\n";
            echo "Well-known file: $wellKnownFile\n";
            
            // Create .well-known directory if it doesn't exist
            if (!is_dir($wellKnownDir)) {
                if (!mkdir($wellKnownDir, 0755, true)) {
                    echo "Failed to create .well-known directory\n";
                    return false;
                }
                echo "Created .well-known directory\n";
            }
            
            // Get current origins
            $originsData = $this->testGetRelatedOrigins();
            if (!$originsData['ok']) {
                echo "Failed to get origins for .well-known file\n";
                return false;
            }
            
            $webauthnConfig = [
                'origins' => $originsData['origins']
            ];
            
            // Write the file
            $jsonContent = json_encode($webauthnConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            if (file_put_contents($wellKnownFile, $jsonContent) !== false) {
                echo "Updated .well-known/webauthn file successfully\n";
                echo "File content:\n$jsonContent\n";
                return true;
            } else {
                echo "Failed to write .well-known/webauthn file\n";
                return false;
            }
            
        } catch (Exception $e) {
            echo "Error updating .well-known file: " . $e->getMessage() . "\n";
            return false;
        }
    }
    
    /**
     * Test the isValidOrigin method
     */
    public function testIsValidOrigin($origin) {
        // Allow domains without https:// prefix for convenience
        if (!preg_match('/^https?:\/\//', $origin)) {
            $origin = 'https://' . $origin;
        }
        
        // Must start with https:// and be a valid URL
        if (!preg_match('/^https:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(:[0-9]+)?$/', $origin)) {
            return false;
        }
        
        // Additional validation using filter_var
        $url = filter_var($origin, FILTER_VALIDATE_URL);
        return $url !== false && parse_url($url, PHP_URL_SCHEME) === 'https';
    }
    
    /**
     * Test the onConfigSave hook
     */
    public function testOnConfigSave() {
        echo "onConfigSave called - updating well-known file\n";
        return $this->testUpdateWellKnownFile();
    }
    
    /**
     * Test the onSetupFormsSave hook
     */
    public function testOnSetupFormsSave() {
        echo "onSetupFormsSave called - updating well-known file\n";
        return $this->testUpdateWellKnownFile();
    }
}
?>
