<?php
/**
 * Plugin Version Check - Verify Enhanced Debugging is Active
 */

// Simple test to verify the plugin has the enhanced debugging
try {
    // Read the plugin file to check for our debug markers
    $pluginFile = __DIR__ . '/passkey.php';
    
    if (!file_exists($pluginFile)) {
        echo json_encode(['error' => 'Plugin file not found']);
        exit;
    }
    
    $content = file_get_contents($pluginFile);
    
    // Check for our enhanced debug markers
    $markers = [
        'onApiRoute ENTRY - Starting API route handling',
        'Got request object:',
        'API permission check PASSED',
        'Matched passkey config endpoint - calling handlePasskeyConfig',
        'handlePasskeyConfig returned:',
        'CRITICAL ERROR in onApiRoute:'
    ];
    
    $foundMarkers = [];
    foreach ($markers as $marker) {
        if (strpos($content, $marker) !== false) {
            $foundMarkers[] = $marker;
        }
    }
    
    // Check file modification time
    $modTime = filemtime($pluginFile);
    $modTimeStr = date('Y-m-d H:i:s', $modTime);
    
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'ok',
        'plugin_file' => $pluginFile,
        'file_size' => filesize($pluginFile),
        'last_modified' => $modTimeStr,
        'enhanced_debug_markers' => count($foundMarkers),
        'total_markers' => count($markers),
        'found_markers' => $foundMarkers,
        'enhanced_debug_active' => count($foundMarkers) === count($markers)
    ]);
    
} catch (Exception $e) {
    header('Content-Type: application/json');
    echo json_encode([
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);
}
?>
