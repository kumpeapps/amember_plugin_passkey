<?php
/**
 * Debug script to test passkey registration types
 */

// Simulate credential data that would come from WebAuthn registration
$testCredentialData = array(
    'credential_id' => 'test_credential_id_123',
    'type' => 'public-key',
    'transports' => json_encode(['usb', 'nfc']),
    'attestation_type' => 'none',
    'trust_path' => json_encode([]),
    'aaguid' => '',
    'public_key' => base64_encode('test_public_key_data'),
    'user_handle' => '123',
    'counter' => 0,
    'name' => 'Test Passkey'
);

echo "Testing credential data structure:\n";
echo "================================\n";

foreach ($testCredentialData as $key => $value) {
    echo "$key: " . gettype($value) . " = " . $value . "\n";
}

echo "\nTesting JSON encoding/decoding:\n";
echo "===============================\n";

// Test JSON encode/decode
$jsonString = json_encode($testCredentialData);
echo "JSON encode result: " . (is_string($jsonString) ? "SUCCESS" : "FAILED") . "\n";

$decoded = json_decode($jsonString, true);
echo "JSON decode result: " . (is_array($decoded) ? "SUCCESS" : "FAILED") . "\n";

if (json_last_error() !== JSON_ERROR_NONE) {
    echo "JSON error: " . json_last_error_msg() . "\n";
}

echo "\nTesting object creation:\n";
echo "========================\n";

$obj = (object) $testCredentialData;
echo "Object creation: " . (is_object($obj) ? "SUCCESS" : "FAILED") . "\n";
echo "Object class: " . get_class($obj) . "\n";

// Test property access
try {
    echo "credential_id property: " . $obj->credential_id . "\n";
    echo "Property access: SUCCESS\n";
} catch (Exception $e) {
    echo "Property access error: " . $e->getMessage() . "\n";
}

echo "\nTesting base64 operations:\n";
echo "==========================\n";

$testData = 'test public key data';
$encoded = base64_encode($testData);
echo "Base64 encode: " . (is_string($encoded) ? "SUCCESS" : "FAILED") . " - " . $encoded . "\n";

$decoded = base64_decode($encoded);
echo "Base64 decode: " . (is_string($decoded) ? "SUCCESS" : "FAILED") . " - " . $decoded . "\n";

echo "\nTesting empty values:\n";
echo "=====================\n";

$emptyTests = [
    'empty string' => '',
    'null value' => null,
    'false value' => false,
    'zero' => 0,
    'empty array' => []
];

foreach ($emptyTests as $name => $value) {
    echo "$name: " . gettype($value) . " - empty() = " . (empty($value) ? "true" : "false") . "\n";
}

echo "\nTest completed successfully!\n";
?>
