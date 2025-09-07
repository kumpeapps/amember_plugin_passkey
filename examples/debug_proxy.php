<?php
/**
 * Debug version of secure passkey auth for troubleshooting
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$debug = [
    'timestamp' => date('Y-m-d H:i:s'),
    'request_method' => $_SERVER['REQUEST_METHOD'],
    'request_uri' => $_SERVER['REQUEST_URI'],
    'action' => $_GET['action'] ?? 'none',
];

// Check if config file exists
$configFile = __DIR__ . '/config.php';
$debug['config_file_exists'] = file_exists($configFile);

if (!file_exists($configFile)) {
    $debug['error'] = 'Config file not found';
    echo json_encode($debug);
    exit;
}

try {
    $config = require $configFile;
    $debug['config_type'] = is_array($config) ? 'array' : 'other';
    
    if (is_array($config)) {
        $debug['config_keys'] = array_keys($config);
        $amemberUrl = $config['amember_base_url'] ?? 'not_set';
        $apiKey = $config['api_key'] ?? 'not_set';
    } else {
        $amemberUrl = defined('AMEMBER_URL') ? AMEMBER_URL : 'not_defined';
        $apiKey = defined('AMEMBER_API_KEY') ? AMEMBER_API_KEY : 'not_defined';
    }
    
    $debug['amember_url'] = $amemberUrl;
    $debug['api_key_set'] = !empty($apiKey) && $apiKey !== 'not_set' && $apiKey !== 'not_defined' && $apiKey !== 'your-api-key-here';
    
} catch (Exception $e) {
    $debug['config_error'] = $e->getMessage();
}

// Test the action
$action = $_GET['action'] ?? 'config';
$debug['testing_action'] = $action;

if ($action === 'config') {
    if (isset($amemberUrl) && isset($apiKey) && $debug['api_key_set']) {
        $debug['test_url'] = rtrim($amemberUrl, '/') . '/api/passkey/config';
        
        // Try to make a simple request
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => 'X-API-Key: ' . $apiKey,
                'timeout' => 10
            ]
        ]);
        
        $response = @file_get_contents($debug['test_url'], false, $context);
        $debug['api_response_received'] = $response !== false;
        
        if ($response !== false) {
            $decoded = json_decode($response, true);
            $debug['api_response_valid_json'] = json_last_error() === JSON_ERROR_NONE;
            if ($debug['api_response_valid_json']) {
                $debug['api_response_data'] = $decoded;
            } else {
                $debug['api_response_raw'] = substr($response, 0, 500);
            }
        } else {
            $debug['api_error'] = error_get_last();
        }
    }
}

echo json_encode($debug, JSON_PRETTY_PRINT);
?>
