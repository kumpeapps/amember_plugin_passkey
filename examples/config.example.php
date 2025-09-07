<?php
/**
 * Configuration file for Passkey Authentication
 * 
 * Copy this file to config.php and update with your actual values.
 * Keep config.php out of version control for security.
 */

return [
    // Your aMember installation URL (no trailing slash)
    'amember_base_url' => 'https://your-amember-site.com',
    
    // Your aMember API key (generate in aMember admin -> Setup/Configuration -> API)
    // Make sure to enable "by-login-pass" permission for this API key
    'api_key' => 'your-api-key-here',
    
    // API endpoint for passkey verification
    'api_endpoint' => '/api/check-access/by-passkey',
    
    // CORS settings for production
    'cors_origin' => '*', // Set to your domain in production, e.g., 'https://yourdomain.com'
    
    // Security settings
    'timeout' => 30, // API request timeout in seconds
    'verify_ssl' => true // Set to false only for development with self-signed certificates
];
?>
