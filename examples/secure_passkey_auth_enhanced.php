<?php
/**
 * Enhanced Secure Passkey Authentication Proxy for aMember
 * 
 * This proxy properly handles the WebAuthn flow:
 * 1. Gets authentication options from aMember (with proper challenge)
 * 2. Verifies the credential response with aMember
 * 
 * SECURITY: API key is stored server-side and never exposed to the browser.
 */

// Load configuration
$configFile = __DIR__ . '/config.php';
if (!file_exists($configFile)) {
    die(json_encode([
        'success' => false,
        'error' => 'Configuration file not found. Please create config.php with your aMember settings.'
    ]));
}

require_once $configFile;

// Validate configuration
if (!defined('AMEMBER_URL') || !defined('AMEMBER_API_KEY')) {
    die(json_encode([
        'success' => false,
        'error' => 'Invalid configuration. Please check your config.php file.'
    ]));
}

// Set CORS headers for secure cross-origin requests
header('Access-Control-Allow-Origin: ' . (defined('ALLOWED_ORIGIN') ? ALLOWED_ORIGIN : '*'));
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Content-Type: application/json');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Get the action from query parameter
$action = $_GET['action'] ?? 'verify_credential';

// Session management for challenge storage
session_start();

// Main logic based on action
try {
    switch ($action) {
        case 'get_auth_options':
            handleGetAuthOptions();
            break;
        case 'verify_credential':
            handleVerifyCredential();
            break;
        default:
            throw new Exception('Invalid action specified');
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}

/**
 * Get authentication options from aMember's passkey plugin
 */
function handleGetAuthOptions()
{
    // Request authentication options from aMember
    $loginInitUrl = rtrim(AMEMBER_URL, '/') . '/misc/passkey?action=login-init';
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $loginInitUrl,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-API-Key: ' . AMEMBER_API_KEY
        ],
        CURLOPT_POSTFIELDS => json_encode([
            '_key' => AMEMBER_API_KEY
        ]),
        CURLOPT_SSL_VERIFYPEER => false, // Only for development - enable in production
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_USERAGENT => 'aMember Passkey Proxy/1.0'
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        throw new Exception("cURL error: $error");
    }
    
    if ($httpCode !== 200) {
        throw new Exception("HTTP error $httpCode when getting auth options");
    }
    
    $data = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Invalid JSON response from aMember");
    }
    
    if (!isset($data['status']) || $data['status'] !== 'ok') {
        throw new Exception($data['error'] ?? 'Failed to get authentication options');
    }
    
    // Store the challenge and options in session for verification
    $_SESSION['passkey_challenge'] = $data['options']['challenge'];
    $_SESSION['passkey_options'] = $data['options'];
    
    // Return the options with proper structure
    echo json_encode([
        'success' => true,
        'options' => $data['options']
    ]);
}

/**
 * Verify passkey credential with aMember
 */
function handleVerifyCredential()
{
    // Get JSON input
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON input');
    }
    
    if (!isset($data['credential'])) {
        throw new Exception('Missing credential data');
    }
    
    $credential = $data['credential'];
    
    // Verify we have a stored challenge
    if (!isset($_SESSION['passkey_challenge'])) {
        throw new Exception('No authentication challenge found. Please get auth options first.');
    }
    
    // Add the original challenge to the credential for aMember verification
    $credential['originalChallenge'] = $_SESSION['passkey_challenge'];
    
    // Try multiple aMember endpoints for maximum compatibility
    $endpoints = [
        '/misc/passkey?action=login-finish',
        '/api/check-access/by-passkey',
        '/misc/passkey?action=check-access'
    ];
    
    $lastError = '';
    
    foreach ($endpoints as $endpoint) {
        $url = rtrim(AMEMBER_URL, '/') . $endpoint;
        
        try {
            $result = makeApiRequest($url, $credential);
            
            if ($result['success']) {
                // Clear session data after successful authentication
                unset($_SESSION['passkey_challenge']);
                unset($_SESSION['passkey_options']);
                
                // Success - return the result
                echo json_encode([
                    'success' => true,
                    'data' => $result['data']
                ]);
                return;
            } else {
                $lastError = $result['error'];
            }
        } catch (Exception $e) {
            $lastError = $e->getMessage();
            continue; // Try next endpoint
        }
    }
    
    // All endpoints failed
    throw new Exception("All authentication endpoints failed. Last error: $lastError");
}

/**
 * Make API request to aMember with proper authentication
 */
function makeApiRequest($url, $credential)
{
    $ch = curl_init();
    
    // Prepare the request data
    $requestData = [
        'credential' => $credential,
        'assertion' => $credential, // Some endpoints expect 'assertion'
        '_key' => AMEMBER_API_KEY
    ];
    
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-API-Key: ' . AMEMBER_API_KEY
        ],
        CURLOPT_POSTFIELDS => json_encode($requestData),
        CURLOPT_SSL_VERIFYPEER => false, // Only for development - enable in production
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_USERAGENT => 'aMember Passkey Proxy/1.0'
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        throw new Exception("cURL error: $error");
    }
    
    if ($httpCode === 404) {
        return ['success' => false, 'error' => "Endpoint not found: $url"];
    }
    
    if ($httpCode !== 200) {
        return ['success' => false, 'error' => "HTTP error $httpCode"];
    }
    
    $data = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['success' => false, 'error' => 'Invalid JSON response'];
    }
    
    // Check for aMember success indicators
    if (isset($data['ok']) && $data['ok'] === true) {
        return ['success' => true, 'data' => $data];
    } elseif (isset($data['status']) && $data['status'] === 'ok') {
        return ['success' => true, 'data' => $data];
    } else {
        $errorMsg = $data['error'] ?? $data['message'] ?? 'Authentication failed';
        return ['success' => false, 'error' => $errorMsg];
    }
}
?>
