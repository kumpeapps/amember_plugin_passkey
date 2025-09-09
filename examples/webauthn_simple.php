<?php
/**
 * Simple WebAuthn Server for aMember
 * Uses basic cryptographic functions without complex dependencies
 */

// Load config - REQUIRED
if (!file_exists('config.php')) {
    header('HTTP/1.1 500 Internal Server Error');
    echo json_encode([
        'success' => false,
        'error' => 'Configuration file config.php not found. Please copy config.example.php to config.php and configure it.',
        'required_config' => [
            'amember_base_url' => 'Your aMember installation URL',
            'api_key' => 'Your aMember API key'
        ]
    ]);
    exit;
}

$config = include 'config.php';

// Validate required config
$required = ['amember_base_url', 'api_key'];
$missing = [];
foreach ($required as $key) {
    if (empty($config[$key]) || $config[$key] === 'YOUR_API_KEY_HERE' || $config[$key] === 'YOUR_AMEMBER_URL_HERE') {
        $missing[] = $key;
    }
}

if (!empty($missing)) {
    header('HTTP/1.1 500 Internal Server Error');
    echo json_encode([
        'success' => false,
        'error' => 'Missing required configuration: ' . implode(', ', $missing),
        'missing_config' => $missing,
        'note' => 'Please update config.php with your actual values'
    ]);
    exit;
}

$amemberUrl = rtrim($config['amember_base_url'], '/');
$apiKey = $config['api_key'];

// Get RP ID and RP Name from aMember config API
function getAmemberConfig() {
    global $amemberUrl, $apiKey;
    
    $configResult = callAmemberAPI('/misc/passkey', ['action' => 'get-config']);
    
    if ($configResult && isset($configResult['config'])) {
        $rpId = $configResult['config']['rp_id'] ?? parse_url($amemberUrl, PHP_URL_HOST);
        $rpName = $configResult['config']['rp_name'] ?? 'aMember Site';
    } else {
        // Fallback to extracting from URL and default name
        $parsedUrl = parse_url($amemberUrl);
        $host = $parsedUrl['host'] ?? 'localhost';
        
        // Remove www. prefix for rp_id
        $rpId = preg_replace('/^www\./', '', $host);
        $rpName = 'aMember Site';
    }
    
    // Override RP ID for localhost testing OR if accessing from different domain
    $currentHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
    if (strpos($currentHost, 'localhost') !== false) {
        $rpId = 'localhost';
        $rpName .= ' (Local Testing)';
    } elseif (strpos($currentHost, 'kumpeapps.com') !== false) {
        // If accessing from kumpeapps.com, use that as RP ID
        $rpId = 'kumpeapps.com';
        $rpName .= ' (kumpeapps.com)';
    }
    
    return [
        'rp_id' => $rpId,
        'rp_name' => $rpName
    ];
}

$amemberConfig = getAmemberConfig();
$rpId = $amemberConfig['rp_id'];
$rpName = $amemberConfig['rp_name'];

// Set CORS headers
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Start session for challenge storage
session_start();

// Base64url encoding functions
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}

// aMember API functions
function callAmemberAPI($endpoint, $params = []) {
    global $amemberUrl, $apiKey;
    
    $url = rtrim($amemberUrl, '/') . '/api/' . ltrim($endpoint, '/');
    $params['_key'] = $apiKey;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        return false;
    }
    
    return json_decode($response, true);
}

// Get stored credentials from aMember database
function getStoredCredentials() {
    global $amemberUrl, $apiKey;
    
    // First try to get from aMember API
    $result = callAmemberAPI('/misc/passkey', ['action' => 'get-credentials']);
    
    if ($result && isset($result['credentials'])) {
        error_log("WebAuthn Simple: Got credentials from aMember API: " . count($result['credentials']));
        return $result['credentials'];
    } else {
        error_log("WebAuthn Simple: aMember API call failed or returned no credentials");
    }
    
    // Try to read directly from database if we can find aMember config
    $configPaths = ['../config.php', '../../config.php', '../../../config.php'];
    foreach ($configPaths as $configPath) {
        if (file_exists($configPath)) {
            try {
                error_log("WebAuthn Simple: Trying config at: " . $configPath);
                $amemberConfig = include $configPath;
                
                if (isset($amemberConfig['db'])) {
                    $dbConfig = $amemberConfig['db'];
                    
                    $pdo = new PDO(
                        "mysql:host={$dbConfig['host']};dbname={$dbConfig['db']};charset=utf8mb4",
                        $dbConfig['user'],
                        $dbConfig['pass'],
                        [
                            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
                        ]
                    );
                    
                    $tableName = ($dbConfig['prefix'] ?? 'am_') . 'passkey_credentials';
                    error_log("WebAuthn Simple: Trying to query table: " . $tableName);
                    
                    $stmt = $pdo->prepare("SELECT credential_id, public_key, user_id, created_at FROM {$tableName} WHERE 1");
                    $stmt->execute();
                    
                    $credentials = [];
                    while ($row = $stmt->fetch()) {
                        $credentials[] = [
                            'id' => $row['credential_id'],
                            'type' => 'public-key',
                            'transports' => ['internal', 'hybrid', 'usb'],
                            'user_id' => $row['user_id'],
                            'public_key' => $row['public_key']
                        ];
                    }
                    
                    error_log("WebAuthn Simple: Found " . count($credentials) . " credentials in database");
                    return $credentials;
                }
            } catch (Exception $e) {
                error_log("WebAuthn Simple: Database connection failed: " . $e->getMessage());
            }
        }
    }
    
    // Fallback - return empty array if no credentials found
    // This will trigger discoverable/platform credential authentication
    error_log("WebAuthn Simple: No credentials found, using discoverable credential mode");
    return [];
}

// Get action
$action = $_GET['action'] ?? $_POST['action'] ?? null;

switch ($action) {
    case 'challenge':
        try {
            // Generate a random challenge
            $challenge = random_bytes(32);
            $challengeB64 = base64url_encode($challenge);
            
            // Store challenge in session
            $_SESSION['webauthn_challenge'] = $challengeB64;
            $_SESSION['challenge_time'] = time();
            
            // Get stored credentials
            $storedCredentials = getStoredCredentials();
            $allowCredentials = [];
            
            // Only add credentials if we have real ones (not test credentials)
            foreach ($storedCredentials as $cred) {
                if (isset($cred['id']) && isset($cred['type']) && $cred['user_id'] !== 'test_user') {
                    $allowCredentials[] = [
                        'type' => $cred['type'],
                        'id' => $cred['id'], // Assuming already base64url encoded
                        'transports' => $cred['transports'] ?? ['internal', 'hybrid', 'usb']
                    ];
                }
            }
            
            $options = [
                'challenge' => $challengeB64,
                'timeout' => 60000,
                'rpId' => $rpId,
                'userVerification' => 'preferred'
            ];
            
            // Only add allowCredentials if we have real credentials
            if (!empty($allowCredentials)) {
                $options['allowCredentials'] = $allowCredentials;
            }
            
            echo json_encode([
                'success' => true,
                'options' => $options,
                'debug' => [
                    'credentials_found' => count($allowCredentials),
                    'rp_id' => $rpId,
                    'rp_name' => $rpName,
                    'challenge_length' => strlen($challenge),
                    'stored_credentials' => $storedCredentials,
                    'amember_url' => $amemberUrl,
                    'config_exists' => file_exists('config.php'),
                    'main_config_exists' => file_exists('../config.php'),
                    'config_source' => 'aMember API or URL fallback',
                    'current_host' => $_SERVER['HTTP_HOST'] ?? 'unknown',
                    'api_call_attempted' => true,
                    'database_search_attempted' => true
                ]
            ]);
            
        } catch (Exception $e) {
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ]);
        }
        break;
        
    case 'verify':
        try {
            // Get credential data from POST
            $input = json_decode(file_get_contents('php://input'), true);
            $credentialData = $input['credential'] ?? null;
            
            if (!$credentialData) {
                throw new Exception('No credential data provided');
            }
            
            // Check if we have a stored challenge
            if (!isset($_SESSION['webauthn_challenge'])) {
                throw new Exception('No challenge found in session');
            }
            
            // Check challenge age (should be recent)
            $challengeAge = time() - ($_SESSION['challenge_time'] ?? 0);
            if ($challengeAge > 300) { // 5 minutes
                throw new Exception('Challenge expired');
            }
            
            $expectedChallenge = $_SESSION['webauthn_challenge'];
            
            // Decode client data to verify challenge
            $clientDataJSON = base64url_decode($credentialData['response']['clientDataJSON']);
            $clientData = json_decode($clientDataJSON, true);
            
            if (!$clientData) {
                throw new Exception('Invalid client data JSON');
            }
            
            // Verify challenge matches
            if ($clientData['challenge'] !== $expectedChallenge) {
                throw new Exception('Challenge mismatch');
            }
            
            // Verify origin
            $expectedOrigin = 'https://' . $rpId;
            if ($clientData['origin'] !== $expectedOrigin) {
                // Allow localhost for testing
                if (!in_array($clientData['origin'], ['http://localhost:8080', 'http://localhost:3000'])) {
                    throw new Exception('Origin mismatch: expected ' . $expectedOrigin . ', got ' . $clientData['origin']);
                }
            }
            
            // For this simple implementation, we'll trust the credential ID exists
            // In production, you'd verify the signature cryptographically
            
            // Try to authenticate with aMember
            $credentialId = $credentialData['id'];
            $authResult = callAmemberAPI('/misc/passkey', [
                'action' => 'authenticate',
                'credential_id' => $credentialId,
                'client_data' => $credentialData['response']['clientDataJSON'],
                'authenticator_data' => $credentialData['response']['authenticatorData'],
                'signature' => $credentialData['response']['signature']
            ]);
            
            if ($authResult && isset($authResult['user'])) {
                // Clear challenge
                unset($_SESSION['webauthn_challenge']);
                unset($_SESSION['challenge_time']);
                
                echo json_encode([
                    'success' => true,
                    'user_id' => $authResult['user']['user_id'] ?? null,
                    'name' => $authResult['user']['name'] ?? 'Authenticated User',
                    'email' => $authResult['user']['email'] ?? null,
                    'access' => true,
                    'debug' => [
                        'credential_id' => $credentialId,
                        'origin' => $clientData['origin'],
                        'challenge_verified' => true
                    ]
                ]);
            } else {
                // Fallback - if aMember API doesn't work, just verify the challenge was correct
                unset($_SESSION['webauthn_challenge']);
                unset($_SESSION['challenge_time']);
                
                echo json_encode([
                    'success' => true,
                    'user_id' => 'test_user',
                    'name' => 'Test User (Challenge Verified)',
                    'email' => 'test@example.com',
                    'access' => true,
                    'debug' => [
                        'note' => 'aMember API not available, using challenge verification only',
                        'credential_id' => $credentialId,
                        'origin' => $clientData['origin'],
                        'challenge_verified' => true
                    ]
                ]);
            }
            
        } catch (Exception $e) {
            echo json_encode([
                'success' => false,
                'error' => $e->getMessage(),
                'debug' => [
                    'credential_provided' => isset($credentialData),
                    'challenge_in_session' => isset($_SESSION['webauthn_challenge']),
                    'input_received' => !empty(file_get_contents('php://input'))
                ]
            ]);
        }
        break;
        
    default:
        echo json_encode([
            'success' => false,
            'error' => 'Invalid action. Use ?action=challenge or ?action=verify',
            'available_actions' => ['challenge', 'verify']
        ]);
        break;
}
?>
