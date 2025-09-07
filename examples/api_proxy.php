<?php
/**
 * Passkey Authentication Proxy
 * 
 * This PHP script acts as a secure proxy between your frontend and the aMember API.
 * It handles API key authentication and forwards passkey verification requests.
 */

// Load configuration from external file
$configFile = __DIR__ . '/config.php';
if (!file_exists($configFile)) {
    http_response_code(500);
    echo json_encode(['error' => 'Configuration file not found. Copy config.example.php to config.php']);
    exit;
}

$config = require $configFile;

// CORS headers for frontend access
header('Access-Control-Allow-Origin: ' . $config['cors_origin']);
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

try {
    // Get request data
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON in request');
    }
    
    if (!isset($data['credential'])) {
        throw new Exception('Missing credential in request');
    }
    
    // Prepare request to aMember API
    $apiUrl = $config['amember_base_url'] . $config['api_endpoint'];
    
    // Try alternative endpoint names if the configured one doesn't work
    $endpoints = [
        $config['api_endpoint'], // /api/check-access/by-passkey
        '/api/passkey-check-access', // Alternative naming
        '/api/check-access-by-passkey', // Another alternative
    ];
    
    $requestData = [
        'credential' => $data['credential']
    ];
    
    $lastError = '';
    foreach ($endpoints as $endpoint) {
        $testUrl = $config['amember_base_url'] . $endpoint;
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $testUrl,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($requestData),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'X-API-Key: ' . $config['api_key'], // Add API key authentication
                'Accept: application/json'
            ],
            CURLOPT_TIMEOUT => $config['timeout'],
            CURLOPT_SSL_VERIFYPEER => $config['verify_ssl'],
            CURLOPT_SSL_VERIFYHOST => $config['verify_ssl'] ? 2 : 0,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        if (!$curlError && $httpCode === 200) {
            // Success! Return the response
            echo $response;
            exit;
        }
        
        $lastError = "Endpoint $endpoint: HTTP $httpCode" . ($curlError ? " - $curlError" : "");
    }
    
    
    // If we get here, all endpoints failed
    throw new Exception('All API endpoints failed. Last error: ' . $lastError);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'ok' => false,
        'error' => $e->getMessage(),
        'user_id' => null,
        'name' => null,
        'email' => null,
        'access' => false,
        'debug_info' => [
            'config_endpoint' => $config['api_endpoint'],
            'base_url' => $config['amember_base_url'],
            'has_api_key' => !empty($config['api_key'])
        ]
    ]);
}
?>
