<?php
/**
 * Secure Passkey Authentication Proxy
 * 
 * This file keeps API keys secure on the server and provides a safe
 * interface for client-side passkey authentication.
 * 
 * SECURITY: API keys are never exposed to client-side code.
 */

// Load configuration
$configFile = __DIR__ . '/config.php';
if (!file_exists($configFile)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Configuration file not found. Copy config.example.php to config.php and configure it.']);
    exit;
}

require_once $configFile;

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
    $url = rtrim(AMEMBER_URL, '/') . $endpoint;
    
    $options = [
        'http' => [
            'method' => $method,
            'header' => [
                'X-API-Key: ' . AMEMBER_API_KEY,
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
        return ['error' => 'Failed to connect to aMember API'];
    }
    
    $decoded = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['error' => 'Invalid JSON response from API'];
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
    
    foreach ($endpoints as $endpoint) {
        $result = makeApiRequest($endpoint, null, 'GET');
        if (isset($result['ok']) && $result['ok']) {
            return $result;
        }
    }
    
    // Fallback configuration if API endpoint not available
    return [
        'ok' => true,
        'rpId' => parse_url(AMEMBER_URL, PHP_URL_HOST),
        'rpName' => 'aMember',
        'timeout' => 60000,
        'userVerification' => 'preferred',
        'attestation' => 'none',
        'endpoints' => [
            'config' => '/api/passkey/config',
            'authenticate' => '/api/check-access/by-passkey'
        ]
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

// Handle different actions
$action = $_GET['action'] ?? $_POST['action'] ?? 'config';

switch ($action) {
    case 'config':
        // Get passkey configuration
        $config = getPasskeyConfig();
        echo json_encode($config);
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
?>
