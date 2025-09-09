<?php
/**
 * Configuration file for WebAuthn Passkey Authentication
 * 
 * SETUP INSTRUCTIONS:
 * 1. Copy this file to config.php
 * 2. Update the values below with your actual aMember installation details
 * 3. Generate an API key in your aMember admin panel (Setup/Configuration -> Advanced -> REST API)
 * 
 * NOTE: RP ID and RP Name are automatically retrieved from aMember configuration
 */

return [
    // Your aMember installation URL (no trailing slash)
    // Example: 'https://members.yoursite.com' or 'https://yoursite.com/members'
    'amember_base_url' => 'YOUR_AMEMBER_URL_HERE',
    
    // Your aMember API key 
    // Generate this in aMember Admin: Setup/Configuration -> Advanced -> REST API
    'api_key' => 'YOUR_API_KEY_HERE',
    
    // API endpoint for passkey verification (usually doesn't need to change)
    'api_endpoint' => '/api/check-access/by-passkey',
    
    // CORS settings for production - add your domains here
    'cors_origins' => [
        'https://www.yoursite.com',
        'https://yoursite.com',
        'http://localhost',      // For local testing
        'file://',              // For file:// testing
    ],
    
    // WebAuthn settings (optional - will use aMember defaults if not specified)
    'timeout' => 60000,                  // 60 seconds timeout
    'userVerification' => 'preferred'    // User verification requirement
];
