<?php
/**
 * Database and WebAuthn Configuration
 * Copy this to config.php and update with your settings
 */

return [
    // Database Configuration
    'host' => 'localhost',
    'database' => 'kumpeapps_amember',  
    'username' => 'kumpeapps_admin',    
    'password' => 'your_password_here', 
    
    // WebAuthn Settings
    'rp_id' => 'localhost',             // For local: 'localhost', for production: 'kumpe3d.com'
    'rp_name' => 'Simple Passkey Demo', 
    'timeout' => 60000,                 
    'user_verification' => 'preferred', 
];
