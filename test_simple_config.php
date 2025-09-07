<?php
/**
 * Simple Configuration Save Test
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set up environment
$_SERVER['HTTP_HOST'] = 'www.kumpeapps.com';
$_SERVER['DOCUMENT_ROOT'] = __DIR__;

echo "=== Simple Configuration Save Test ===\n\n";

// Test 1: Create .well-known directory and file manually
echo "1. Testing .well-known file creation:\n";

$wellKnownDir = __DIR__ . '/.well-known';
$wellKnownFile = $wellKnownDir . '/webauthn';

// Create directory
if (!is_dir($wellKnownDir)) {
    if (mkdir($wellKnownDir, 0755, true)) {
        echo "✓ Created .well-known directory\n";
    } else {
        echo "✗ Failed to create .well-known directory\n";
    }
} else {
    echo "✓ .well-known directory already exists\n";
}

// Test 2: Create sample configuration
$config = [
    'origins' => [
        'https://www.kumpeapps.com',
        'https://kumpe3d.com',
        'https://www.kumpe3d.com'
    ]
];

$jsonContent = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

if (file_put_contents($wellKnownFile, $jsonContent) !== false) {
    echo "✓ Created .well-known/webauthn file\n";
    echo "Content:\n$jsonContent\n\n";
} else {
    echo "✗ Failed to create .well-known/webauthn file\n";
}

// Test 3: Verify file can be read
echo "2. Testing file read:\n";
if (file_exists($wellKnownFile)) {
    $content = file_get_contents($wellKnownFile);
    echo "✓ File exists and can be read\n";
    echo "Current content:\n$content\n\n";
} else {
    echo "✗ File does not exist\n";
}

// Test 4: Test different origins
echo "3. Testing with different origins:\n";
$testOrigins = [
    'test1.example.com',
    'test2.example.com'
];

$updatedConfig = [
    'origins' => array_merge($config['origins'], array_map(function($origin) {
        return 'https://' . $origin;
    }, $testOrigins))
];

$updatedJson = json_encode($updatedConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

if (file_put_contents($wellKnownFile, $updatedJson) !== false) {
    echo "✓ Updated .well-known/webauthn file with new origins\n";
    echo "Updated content:\n$updatedJson\n\n";
} else {
    echo "✗ Failed to update .well-known/webauthn file\n";
}

// Test 5: Test API endpoint simulation
echo "4. Testing API endpoint simulation:\n";

// Simulate the API call that should update the file
function simulateApiCall($action, $origin = null) {
    global $wellKnownFile;
    
    echo "Simulating API call: $action" . ($origin ? " with origin: $origin" : "") . "\n";
    
    // Read current config
    if (file_exists($wellKnownFile)) {
        $currentConfig = json_decode(file_get_contents($wellKnownFile), true);
    } else {
        $currentConfig = ['origins' => ['https://www.kumpeapps.com']];
    }
    
    if ($action === 'add-origin' && $origin) {
        if (!in_array($origin, $currentConfig['origins'])) {
            $currentConfig['origins'][] = $origin;
            echo "  → Added origin: $origin\n";
        } else {
            echo "  → Origin already exists: $origin\n";
        }
    } elseif ($action === 'remove-origin' && $origin) {
        $key = array_search($origin, $currentConfig['origins']);
        if ($key !== false) {
            unset($currentConfig['origins'][$key]);
            $currentConfig['origins'] = array_values($currentConfig['origins']);
            echo "  → Removed origin: $origin\n";
        } else {
            echo "  → Origin not found: $origin\n";
        }
    }
    
    // Save updated config
    $updatedJson = json_encode($currentConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (file_put_contents($wellKnownFile, $updatedJson) !== false) {
        echo "  → File updated successfully\n";
        return true;
    } else {
        echo "  → Failed to update file\n";
        return false;
    }
}

// Test adding origins
simulateApiCall('add-origin', 'https://new.example.com');
simulateApiCall('add-origin', 'https://another.example.com');

// Show current state
if (file_exists($wellKnownFile)) {
    $content = file_get_contents($wellKnownFile);
    echo "Current file state:\n$content\n\n";
}

// Test removing origins
simulateApiCall('remove-origin', 'https://new.example.com');

// Show final state
if (file_exists($wellKnownFile)) {
    $content = file_get_contents($wellKnownFile);
    echo "Final file state:\n$content\n\n";
}

echo "=== Test Complete ===\n";

// Test 6: Verify the file is accessible via HTTP
echo "5. Testing HTTP accessibility:\n";
$testUrl = "http://localhost:8080/.well-known/webauthn";
echo "File should be accessible at: $testUrl\n";
echo "You can test this manually by starting 'php -S localhost:8080' and visiting the URL\n";
?>
