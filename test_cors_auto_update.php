<?php
/**
 * Test script to verify automatic CORS header creation
 * This simulates the plugin's updateWellKnownFile function
 */

// Simulate the well-known directory update process
function testCorsFunctionality() {
    $testDir = __DIR__ . '/test_well_known';
    $htaccessFile = $testDir . '/.htaccess';
    
    // Create test directory
    if (!is_dir($testDir)) {
        mkdir($testDir, 0755, true);
        echo "✅ Created test directory: $testDir\n";
    }
    
    // Simulate existing .htaccess content (like on the server)
    $existingContent = '<Files "apple-app-site-association">
ForceType "application/json"
</Files>';
    
    file_put_contents($htaccessFile, $existingContent);
    echo "✅ Created initial .htaccess with Apple content\n";
    
    // Test the updateWellKnownHtaccess functionality
    updateWellKnownHtaccess($testDir);
    
    // Check the result
    $finalContent = file_get_contents($htaccessFile);
    echo "\n📄 Final .htaccess content:\n";
    echo "---\n";
    echo $finalContent;
    echo "---\n";
    
    // Verify CORS headers are present
    if (strpos($finalContent, 'Access-Control-Allow-Origin') !== false) {
        echo "✅ CORS headers successfully added!\n";
    } else {
        echo "❌ CORS headers not found!\n";
    }
    
    // Test running it again (should not duplicate)
    echo "\n🔄 Testing duplicate protection...\n";
    updateWellKnownHtaccess($testDir);
    
    $finalContent2 = file_get_contents($htaccessFile);
    if ($finalContent === $finalContent2) {
        echo "✅ Duplicate protection working - content unchanged\n";
    } else {
        echo "❌ Content was modified on second run (duplicates created)\n";
    }
    
    // Cleanup
    unlink($htaccessFile);
    rmdir($testDir);
    echo "✅ Cleanup completed\n";
}

/**
 * Replica of the updateWellKnownHtaccess function from the plugin
 */
function updateWellKnownHtaccess($wellKnownDir)
{
    try {
        $htaccessFile = $wellKnownDir . '/.htaccess';
        echo "🔧 Updating .htaccess file for CORS: $htaccessFile\n";
        
        // Check if .htaccess already exists and read current content
        $existingContent = '';
        $webauthnSectionExists = false;
        
        if (file_exists($htaccessFile)) {
            $existingContent = file_get_contents($htaccessFile);
            // Check if webauthn section already exists
            if (strpos($existingContent, '<Files "webauthn">') !== false) {
                $webauthnSectionExists = true;
                echo "ℹ️ WebAuthn CORS section already exists in .htaccess\n";
                return true; // Already configured
            }
        }
        
        // Prepare the WebAuthn CORS section
        $webauthnSection = "\n" . '<Files "webauthn">' . "\n" .
            'ForceType "application/json"' . "\n" .
            'Header always set Access-Control-Allow-Origin "*"' . "\n" .
            'Header always set Access-Control-Allow-Methods "GET, OPTIONS"' . "\n" .
            'Header always set Access-Control-Allow-Headers "Content-Type, Accept"' . "\n" .
            'Header always set Cache-Control "public, max-age=3600"' . "\n" .
            '</Files>' . "\n";
        
        // If .htaccess doesn't exist, create it with just the WebAuthn section
        if (!file_exists($htaccessFile)) {
            $newContent = trim($webauthnSection);
            echo "🆕 Creating new .htaccess with WebAuthn CORS headers\n";
        } else {
            // Append WebAuthn section to existing content
            $newContent = rtrim($existingContent) . $webauthnSection;
            echo "➕ Appending WebAuthn CORS headers to existing .htaccess\n";
        }
        
        // Write the updated .htaccess file
        $writeResult = file_put_contents($htaccessFile, $newContent);
        
        if ($writeResult !== false) {
            echo "✅ Successfully updated .htaccess with CORS headers\n";
            echo "📊 .htaccess file size: $writeResult bytes\n";
            return true;
        } else {
            echo "❌ Failed to write .htaccess file\n";
            return false;
        }
        
    } catch (Exception $e) {
        echo "❌ Error updating .htaccess file: " . $e->getMessage() . "\n";
        return false;
    }
}

echo "🧪 Testing Automatic CORS Header Creation\n";
echo "==========================================\n\n";

testCorsFunctionality();

echo "\n🎉 Test completed!\n";
?>
