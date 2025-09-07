<?php
/**
 * Enhanced Configuration Example for aMember Passkey Integration
 * 
 * Copy this file to config.php and update with your aMember settings.
 * This enhanced version includes all WebAuthn configuration options
 * that match aMember's passkey plugin settings.
 */

// aMember Base Configuration
define('AMEMBER_URL', 'https://your-amember-site.com');
define('AMEMBER_API_KEY', 'your-api-key-here');

// CORS Configuration (for security)
define('ALLOWED_ORIGIN', '*'); // Change to your specific domain in production

// WebAuthn Configuration (should match your aMember passkey plugin settings)
// These settings will be used if aMember's plugin doesn't provide them

// Relying Party Configuration
define('RP_NAME', 'Your Site Name'); // Display name for your site
define('RP_ID', 'your-amember-site.com'); // Should match your domain

// Timeout Configuration (in milliseconds)
define('WEBAUTHN_TIMEOUT', 60000); // 60 seconds default

// User Verification Requirements
// Options: 'required', 'preferred', 'discouraged'
define('USER_VERIFICATION', 'preferred');

// Resident Key (Discoverable Credentials) Settings
// Options: 'required', 'preferred', 'discouraged'
define('RESIDENT_KEY', 'discouraged'); // Default for better hardware key support

// Require Resident Key (boolean)
define('REQUIRE_RESIDENT_KEY', false);

// Attestation Conveyance Preference
// Options: 'none', 'indirect', 'direct', 'enterprise'
define('ATTESTATION', 'none');

// Authenticator Attachment
// Options: '', 'platform', 'cross-platform'
// Empty string means no preference (allows both)
define('AUTHENTICATOR_ATTACHMENT', '');

// Algorithm Preferences (COSE Algorithm Identifiers)
// Common values: -7 (ES256), -35 (ES384), -36 (ES512), -257 (RS256)
define('ALGORITHM_PREFERENCES', [-7, -257]); // ES256 and RS256

// Debug Configuration
define('DEBUG_MODE', true); // Set to false in production
define('LOG_REQUESTS', true); // Log API requests for debugging

/**
 * Configuration Validation
 */
function validateConfig() {
    $errors = [];
    
    if (!defined('AMEMBER_URL') || empty(AMEMBER_URL)) {
        $errors[] = 'AMEMBER_URL is required';
    }
    
    if (!defined('AMEMBER_API_KEY') || empty(AMEMBER_API_KEY)) {
        $errors[] = 'AMEMBER_API_KEY is required';
    }
    
    if (!empty($errors)) {
        die(json_encode([
            'success' => false,
            'error' => 'Configuration errors: ' . implode(', ', $errors)
        ]));
    }
}

/**
 * Get WebAuthn Configuration Array
 * This matches the structure used by aMember's passkey plugin
 */
function getWebAuthnConfig() {
    return [
        'rp' => [
            'name' => defined('RP_NAME') ? RP_NAME : 'aMember Site',
            'id' => defined('RP_ID') ? RP_ID : parse_url(AMEMBER_URL, PHP_URL_HOST)
        ],
        'timeout' => defined('WEBAUTHN_TIMEOUT') ? WEBAUTHN_TIMEOUT : 60000,
        'userVerification' => defined('USER_VERIFICATION') ? USER_VERIFICATION : 'preferred',
        'residentKey' => defined('RESIDENT_KEY') ? RESIDENT_KEY : 'discouraged',
        'requireResidentKey' => defined('REQUIRE_RESIDENT_KEY') ? REQUIRE_RESIDENT_KEY : false,
        'attestation' => defined('ATTESTATION') ? ATTESTATION : 'none',
        'authenticatorAttachment' => defined('AUTHENTICATOR_ATTACHMENT') ? AUTHENTICATOR_ATTACHMENT : '',
        'algorithms' => defined('ALGORITHM_PREFERENCES') ? ALGORITHM_PREFERENCES : [-7, -257]
    ];
}

/**
 * Get Debug Configuration
 */
function getDebugConfig() {
    return [
        'debug_mode' => defined('DEBUG_MODE') ? DEBUG_MODE : false,
        'log_requests' => defined('LOG_REQUESTS') ? LOG_REQUESTS : false
    ];
}

// Validate configuration on load
validateConfig();

/**
 * Example aMember Plugin Settings
 * 
 * In your aMember admin panel (Setup/Configuration → Plugins → Miscellaneous → Passkey),
 * configure these settings to match your security requirements:
 * 
 * Relying Party Settings:
 * - RP Name: "Your Site Name"
 * - RP ID: "your-domain.com" (auto-detected)
 * 
 * Timeout Settings:
 * - Authentication Timeout: 60000ms (60 seconds)
 * 
 * User Verification:
 * - User Verification: "preferred" (recommended)
 * 
 * Authenticator Settings:
 * - Resident Key: "discouraged" (better hardware key support)
 * - Require Resident Key: false
 * - Authenticator Attachment: "" (no preference)
 * 
 * Security Settings:
 * - Attestation: "none" (recommended for most cases)
 * 
 * These settings provide a good balance of security and compatibility
 * with various authenticators (phones, laptops, hardware keys).
 */
?>
