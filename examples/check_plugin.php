<?php
/**
 * Simple Plugin Version Check
 * Checks if enhanced debugging markers are present in the plugin file
 */

header('Content-Type: application/json');

try {
    $pluginFile = __FILE__ ? dirname(__FILE__) . '/passkey.php' : './passkey.php';
    
    if (!file_exists($pluginFile)) {
        echo json_encode([
            'error' => 'Plugin file not found',
            'searched_path' => $pluginFile,
            'current_dir' => getcwd(),
            'file_exists' => false
        ]);
        exit;
    }
    
    $content = file_get_contents($pluginFile);
    $fileSize = filesize($pluginFile);
    $modTime = filemtime($pluginFile);
    
    // Check for enhanced debug markers
    $debugMarkers = [
        'onApiRoute ENTRY - Starting API route handling',
        'Got request object:',
        'API permission check PASSED', 
        'Matched passkey config endpoint - calling handlePasskeyConfig',
        'handlePasskeyConfig returned:',
        'CRITICAL ERROR in onApiRoute:'
    ];
    
    $foundMarkers = [];
    foreach ($debugMarkers as $marker) {
        if (strpos($content, $marker) !== false) {
            $foundMarkers[] = $marker;
        }
    }
    
    // Check for basic plugin structure
    $hasClass = strpos($content, 'class Am_Plugin_Passkey') !== false;
    $hasConstructor = strpos($content, 'public function __construct') !== false;
    $hasApiRoute = strpos($content, 'function onApiRoute') !== false;
    $hasHandleConfig = strpos($content, 'function handlePasskeyConfig') !== false;
    
    echo json_encode([
        'status' => 'ok',
        'plugin_file' => $pluginFile,
        'file_size' => $fileSize,
        'last_modified' => date('Y-m-d H:i:s', $modTime),
        'enhanced_debug_markers' => count($foundMarkers),
        'total_markers' => count($debugMarkers),
        'found_markers' => $foundMarkers,
        'enhanced_debug_active' => count($foundMarkers) === count($debugMarkers),
        'plugin_structure' => [
            'has_class' => $hasClass,
            'has_constructor' => $hasConstructor,
            'has_api_route' => $hasApiRoute,
            'has_handle_config' => $hasHandleConfig
        ],
        'php_info' => [
            'version' => PHP_VERSION,
            'sapi' => php_sapi_name(),
            'current_dir' => getcwd()
        ]
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);
}
?>
