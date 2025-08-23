<?php
/**
 * Debug script to test WebAuthn parameter generation
 * Run this script to verify the generated options are valid
 */

// Mock the essential parts we need
class MockUser {
    public function pk() { return '1'; }
}

class MockSession {
    public $passkey_challenge;
}

function testWebAuthnOptions() {
    echo "Testing WebAuthn Options Generation\n";
    echo "===================================\n\n";
    
    // Generate challenge
    $challengeBytes = random_bytes(32);
    $challenge = base64_encode($challengeBytes);
    
    // Ensure user ID is properly encoded
    $userId = '1';
    $userIdEncoded = base64_encode(strval($userId));
    
    $optionsArray = array(
        'challenge' => $challenge,
        'rp' => array(
            'name' => 'aMember',
            'id' => 'www.kumpeapps.com'
        ),
        'user' => array(
            'id' => $userIdEncoded,
            'name' => 'justinkumpe',
            'displayName' => 'Justin Kumpe'
        ),
        'pubKeyCredParams' => array(
            array('alg' => -7, 'type' => 'public-key'),   // ES256 (ECDSA with SHA-256)
            array('alg' => -257, 'type' => 'public-key'), // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
            array('alg' => -37, 'type' => 'public-key'),  // PS256 (RSASSA-PSS with SHA-256)
            array('alg' => -35, 'type' => 'public-key'),  // ES384 (ECDSA with SHA-384)
            array('alg' => -36, 'type' => 'public-key'),  // ES512 (ECDSA with SHA-512)
            array('alg' => -8, 'type' => 'public-key')    // EdDSA (Ed25519 signature algorithms)
        ),
        'timeout' => 60000,
        'attestation' => 'none',
        'authenticatorSelection' => array(
            'authenticatorAttachment' => null, // Allow both platform and roaming authenticators
            'userVerification' => 'preferred', // Prefer user verification but don't require it
            'residentKey' => 'preferred',      // Prefer resident keys for better UX
            'requireResidentKey' => false      // But don't require them for compatibility
        ),
        'extensions' => new stdClass()  // Empty object, not array
    );
    
    // Test validation
    echo "1. Challenge Validation:\n";
    echo "   Original bytes length: " . strlen($challengeBytes) . "\n";
    echo "   Base64 challenge: $challenge\n";
    echo "   Challenge length: " . strlen($challenge) . "\n";
    echo "   Is valid base64: " . (base64_encode(base64_decode($challenge)) === $challenge ? 'YES' : 'NO') . "\n";
    echo "   Decoded back length: " . strlen(base64_decode($challenge)) . "\n\n";
    
    echo "2. User ID Validation:\n";
    echo "   Original user ID: $userId\n";
    echo "   Encoded user ID: $userIdEncoded\n";
    echo "   User ID length: " . strlen($userIdEncoded) . "\n";
    echo "   Is valid base64: " . (base64_encode(base64_decode($userIdEncoded)) === $userIdEncoded ? 'YES' : 'NO') . "\n";
    echo "   Decoded back: " . base64_decode($userIdEncoded) . "\n\n";
    
    echo "3. Options Structure:\n";
    echo "   RP name: " . $optionsArray['rp']['name'] . "\n";
    echo "   RP id: " . $optionsArray['rp']['id'] . "\n";
    echo "   User name: " . $optionsArray['user']['name'] . "\n";
    echo "   User display name: " . $optionsArray['user']['displayName'] . "\n";
    echo "   Algorithms count: " . count($optionsArray['pubKeyCredParams']) . "\n";
    echo "   Timeout: " . $optionsArray['timeout'] . "\n";
    echo "   Attestation: " . $optionsArray['attestation'] . "\n\n";
    
    echo "4. Authenticator Selection:\n";
    echo "   Attachment: " . ($optionsArray['authenticatorSelection']['authenticatorAttachment'] ?? 'null') . "\n";
    echo "   User verification: " . $optionsArray['authenticatorSelection']['userVerification'] . "\n";
    echo "   Resident key: " . $optionsArray['authenticatorSelection']['residentKey'] . "\n";
    echo "   Require resident key: " . ($optionsArray['authenticatorSelection']['requireResidentKey'] ? 'true' : 'false') . "\n\n";
    
    echo "5. JSON Encoding Test:\n";
    $json = json_encode($optionsArray);
    if ($json === false) {
        echo "   ERROR: JSON encoding failed: " . json_last_error_msg() . "\n";
        return false;
    } else {
        echo "   JSON encoding: SUCCESS\n";
        echo "   JSON length: " . strlen($json) . "\n";
        
        // Test decoding back
        $decoded = json_decode($json, true);
        if ($decoded === null) {
            echo "   ERROR: JSON decoding failed: " . json_last_error_msg() . "\n";
            return false;
        } else {
            echo "   JSON round-trip: SUCCESS\n";
        }
    }
    
    echo "\n6. Full JSON Output:\n";
    echo $json . "\n\n";
    
    echo "7. JavaScript-style Formatting Test:\n";
    $jsTestCode = '
<!DOCTYPE html>
<html>
<head>
    <title>WebAuthn Options Test</title>
</head>
<body>
    <h1>WebAuthn Options Test</h1>
    <button onclick="testOptions()">Test Options</button>
    <div id="result"></div>
    
    <script>
    function testOptions() {
        const options = ' . $json . ';
        const resultDiv = document.getElementById("result");
        
        try {
            // Test challenge decoding
            const challengeBytes = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
            console.log("Challenge decoded length:", challengeBytes.length);
            
            // Test user ID decoding
            const userIdBytes = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0));
            console.log("User ID decoded length:", userIdBytes.length);
            
            // Test options structure
            console.log("Full options:", options);
            console.log("Authenticator selection:", options.authenticatorSelection);
            console.log("Public key params:", options.pubKeyCredParams);
            
            resultDiv.innerHTML = "<p style=\'color: green;\'>✅ Options validation passed! Check console for details.</p>";
            
            // This would be the actual WebAuthn call
            // navigator.credentials.create({publicKey: options});
            
        } catch (error) {
            console.error("Options validation failed:", error);
            resultDiv.innerHTML = "<p style=\'color: red;\'>❌ Options validation failed: " + error.message + "</p>";
        }
    }
    </script>
</body>
</html>';
    
    file_put_contents(__DIR__ . '/webauthn_test.html', $jsTestCode);
    echo "   Created webauthn_test.html for browser testing\n";
    
    return true;
}

// Run the test
if (testWebAuthnOptions()) {
    echo "\n✅ WebAuthn options generation test completed successfully!\n";
    echo "Open webauthn_test.html in your browser to test JavaScript compatibility.\n";
} else {
    echo "\n❌ WebAuthn options generation test failed!\n";
}
?>
