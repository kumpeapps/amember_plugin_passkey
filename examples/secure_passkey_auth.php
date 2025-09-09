<?php
/**
 * Secure Passkey Authentication Proxy
 * 
 * This file keeps API keys secure on the server and provides a safe
 * interface for client-side passkey authentication.
 * 
 * SECURITY: API keys are never exposed to client-side code.
 */

// Error reporting for debugging (remove in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Load configuration
$configFile = __DIR__ . '/config.php';
if (!file_exists($configFile)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Configuration file not found. Copy config.example.php to config.php and configure it.']);
    exit;
}

$config = require $configFile;

// Handle both array config and constants
if (is_array($config)) {
    $amemberUrl = $config['amember_base_url'];
    $apiKey = $config['api_key'];
} else {
    // Fallback to constants
    $amemberUrl = defined('AMEMBER_URL') ? AMEMBER_URL : '';
    $apiKey = defined('AMEMBER_API_KEY') ? AMEMBER_API_KEY : '';
}

if (empty($amemberUrl) || empty($apiKey)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Configuration incomplete. Please set aMember URL and API key.']);
    exit;
}

// CORS Headers for cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
header('Content-Type: application/json');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

/**
 * Make API request to aMember with error handling
 */
function makeApiRequest($endpoint, $data = null, $method = 'GET') {
    global $amemberUrl, $apiKey;
    
    $url = rtrim($amemberUrl, '/') . $endpoint;
    
    $options = [
        'http' => [
            'method' => $method,
            'header' => [
                'X-API-Key: ' . $apiKey,
                'Content-Type: application/json'
            ],
            'timeout' => 30
        ]
    ];
    
    if ($data && $method === 'POST') {
        $options['http']['content'] = json_encode($data);
    }
    
    $context = stream_context_create($options);
    $response = @file_get_contents($url, false, $context);
    
    if ($response === false) {
        $error = error_get_last();
        return ['error' => 'Failed to connect to aMember API: ' . ($error['message'] ?? 'Unknown error')];
    }
    
    $decoded = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['error' => 'Invalid JSON response from API: ' . substr($response, 0, 200)];
    }
    
    return $decoded;
}

/**
 * Get passkey configuration from aMember
 */
function getPasskeyConfig() {
    $endpoints = [
        '/api/passkey/config',
        '/api/passkey-config',
        '/misc/passkey?action=config'
    ];
    
    $lastError = '';
    foreach ($endpoints as $endpoint) {
        $result = makeApiRequest($endpoint, null, 'GET');
        
        // Log the full response for debugging
        error_log("Passkey Config Test - Endpoint: $endpoint, Response: " . json_encode($result));
        
        if (isset($result['ok']) && $result['ok']) {
            return $result;
        }
        
        $lastError = isset($result['error']) ? $result['error'] : 
                    (isset($result['message']) ? $result['message'] : 'Unknown error');
    }
    
    // Return the actual error instead of fallback
    return [
        'ok' => false,
        'error' => 'Configuration endpoint failed: ' . $lastError,
        'debug' => 'All endpoints returned errors, check aMember error logs'
    ];
}

/**
 * Authenticate user with passkey credential
 */
function authenticatePasskey($credentialData) {
    $endpoints = [
        '/api/check-access/by-passkey',
        '/api/check-access-by-passkey',
        '/api/passkey-check-access',
        '/misc/passkey?action=check-access'
    ];
    
    foreach ($endpoints as $endpoint) {
        $result = makeApiRequest($endpoint, ['credential' => $credentialData], 'POST');
        
        if (isset($result['ok']) && $result['ok']) {
            return $result;
        }
        
        // If we get a meaningful error (not just connection failure), return it
        if (isset($result['error']) && !in_array($result['error'], ['Failed to connect to aMember API', 'Invalid JSON response from API'])) {
            return $result;
        }
    }
    
    return ['error' => 'All authentication endpoints failed', 'ok' => false];
}

/**
 * Get available credentials for better desktop 1Password compatibility
 */
function getAvailableCredentials() {
    $endpoints = [
        '/api/passkey/credentials',
        '/api/passkey-credentials', 
        '/misc/passkey?action=get-credentials'
    ];
    
    $lastError = '';
    foreach ($endpoints as $endpoint) {
        $result = makeApiRequest($endpoint, null, 'GET');
        
        if (isset($result['ok']) && $result['ok']) {
            return $result;
        }
        
        $lastError = isset($result['error']) ? $result['error'] : 
                    (isset($result['message']) ? $result['message'] : 'Unknown error');
    }
    
    // Return empty credentials if endpoint not found (fallback for compatibility)
    return [
        'ok' => true,
        'credentials' => [],
        'note' => 'Credentials endpoint not available, using discoverable credentials'
    ];
}

/**
 * Add a related origin for cross-domain passkey usage
 */
function addRelatedOrigin($origin) {
    $endpoints = [
        '/api/passkey/config',
        '/api/passkey-config',
        '/misc/passkey?action=config'
    ];
    
    $data = [
        'action' => 'add-origin',
        'origin' => $origin
    ];
    
    $lastError = '';
    foreach ($endpoints as $endpoint) {
        $result = makeApiRequest($endpoint, $data, 'POST');
        
        if (isset($result['ok']) && $result['ok']) {
            return $result;
        }
        
        $lastError = isset($result['error']) ? $result['error'] : 
                    (isset($result['message']) ? $result['message'] : 'Unknown error');
    }
    
    return [
        'ok' => false,
        'error' => 'Failed to add related origin: ' . $lastError
    ];
}

/**
 * Remove a related origin
 */
function removeRelatedOrigin($origin) {
    $endpoints = [
        '/api/passkey/config',
        '/api/passkey-config',
        '/misc/passkey?action=config'
    ];
    
    $data = [
        'action' => 'remove-origin',
        'origin' => $origin
    ];
    
    $lastError = '';
    foreach ($endpoints as $endpoint) {
        $result = makeApiRequest($endpoint, $data, 'POST');
        
        if (isset($result['ok']) && $result['ok']) {
            return $result;
        }
        
        $lastError = isset($result['error']) ? $result['error'] : 
                    (isset($result['message']) ? $result['message'] : 'Unknown error');
    }
    
    return [
        'ok' => false,
        'error' => 'Failed to remove related origin: ' . $lastError
    ];
}

// Handle different actions
$action = $_GET['action'] ?? $_POST['action'] ?? 'config';

switch ($action) {
    case 'config':
        // Get passkey configuration
        $config = getPasskeyConfig();
        echo json_encode($config);
        break;
        
    case 'add-origin':
        // Add related origin
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST for add-origin.']);
            break;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        if (!isset($input['origin'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing origin parameter']);
            break;
        }
        
        $result = addRelatedOrigin($input['origin']);
        echo json_encode($result);
        break;
        
    case 'remove-origin':
        // Remove related origin
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed. Use POST for remove-origin.']);
            break;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        if (!isset($input['origin'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing origin parameter']);
            break;
        }
        
        $result = removeRelatedOrigin($input['origin']);
        echo json_encode($result);
        break;
        
    case 'get-credentials':
        // Get available credentials for better desktop compatibility
        $credentials = getAvailableCredentials();
        echo json_encode($credentials);
        break;
        
    case 'amember-challenge':
        // Generate aMember-compatible WebAuthn challenge
        error_log('Secure Passkey Auth: Generating aMember-compatible challenge');
        
        // Generate base64url-encoded challenge (like aMember does)
        $challengeBytes = random_bytes(32);
        $challenge = base64url_encode($challengeBytes);
        
        // Get aMember configuration
        $config = getPasskeyConfig();
        
        // Return aMember-compatible challenge format
        $response = [
            'status' => 'ok',
            'options' => [
                'challenge' => $challenge,
                'timeout' => intval($config['timeout'] ?? 60000),
                'userVerification' => $config['userVerification'] ?? 'preferred',
                'allowCredentials' => [], // Empty for discoverable credentials like aMember
                'extensions' => []
            ]
        ];
        
        error_log('Secure Passkey Auth: aMember-compatible challenge generated: ' . json_encode($response));
        echo json_encode($response);
        break;
        
    case 'amember-verify':
        // Verify using aMember's REST API
        error_log('Secure Passkey Auth: Verifying with aMember REST API');
        
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        if (!isset($input['credential'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Credential data required']);
            exit;
        }
        
        // Send to aMember for verification
        $verifyResponse = makeAmemberRequest('/api/check-access/by-passkey', [
            'credential' => $input['credential']
        ]);
        
        if (!$verifyResponse['success']) {
            http_response_code(500);
            echo json_encode(['error' => 'aMember verification failed: ' . $verifyResponse['error']]);
            exit;
        }
        
        $result = json_decode($verifyResponse['body'], true);
        echo json_encode($result);
        break;

    case 'authenticate':
        // Handle passkey authentication
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        if (!isset($input['credential'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing credential data']);
            break;
        }
        
        $result = authenticatePasskey($input['credential']);
        echo json_encode($result);
        break;
        
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
}

// Helper functions for aMember compatibility

/**
 * Base64url encode (for WebAuthn challenge format)
 */
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Base64url decode
 */
function base64url_decode($data) {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}

/**
 * Make request to aMember API with proper authentication
 */
function makeAmemberRequest($endpoint, $data = []) {
    global $amemberUrl, $apiKey;
    
    $url = rtrim($amemberUrl, '/') . $endpoint;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'X-API-Key: ' . $apiKey
    ]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // For development
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        return ['success' => false, 'error' => 'cURL error: ' . $error];
    }
    
    if ($httpCode !== 200) {
        return ['success' => false, 'error' => 'HTTP ' . $httpCode . ': ' . $response];
    }
    
    return ['success' => true, 'body' => $response];
}

?>
