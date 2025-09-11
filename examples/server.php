<?php
/**
 * Simple WebAuthn Server
 * Step 1: Basic same-domain authentication
 * Auto-installs Composer dependencies if needed
 */

// Auto-install Composer and dependencies
function autoInstallComposer() {
    $composerFile = __DIR__ . '/composer.json';
    $vendorDir = __DIR__ . '/vendor';
    $composerPhar = __DIR__ . '/composer.phar';
    
    // If we have a composer.json but no vendor directory, install dependencies
    if (file_exists($composerFile) && !is_dir($vendorDir)) {
        
        // Check if Composer is installed globally
        $composerCmd = 'composer';
        exec('which composer 2>/dev/null', $output, $returnCode);
        
        if ($returnCode !== 0) {
            // Install Composer locally if not found globally
            if (!file_exists($composerPhar)) {
                echo "Installing Composer...\n";
                
                // Download Composer installer
                $installer = file_get_contents('https://getcomposer.org/installer');
                if ($installer === false) {
                    die("Failed to download Composer installer\n");
                }
                
                // Run installer
                $tempFile = tempnam(sys_get_temp_dir(), 'composer_installer');
                file_put_contents($tempFile, $installer);
                
                $output = shell_exec("php $tempFile --install-dir=" . __DIR__);
                unlink($tempFile);
                
                if (!file_exists($composerPhar)) {
                    die("Failed to install Composer\n");
                }
                
                echo "Composer installed successfully\n";
            }
            
            $composerCmd = "php $composerPhar";
        }
        
        // Install dependencies
        echo "Installing dependencies...\n";
        $currentDir = getcwd();
        chdir(__DIR__);
        
        $output = shell_exec("$composerCmd install --no-dev --optimize-autoloader 2>&1");
        echo $output;
        
        chdir($currentDir);
        
        if (!is_dir($vendorDir)) {
            die("Failed to install Composer dependencies\n");
        }
        
        echo "Dependencies installed successfully\n";
    }
    
    // Include autoloader if it exists
    if (file_exists($vendorDir . '/autoload.php')) {
        require_once $vendorDir . '/autoload.php';
    }
}

// Auto-create config.php if it doesn't exist
function autoCreateConfig() {
    $configFile = __DIR__ . '/config.php';
    $exampleFile = __DIR__ . '/config.example.php';
    
    if (!file_exists($configFile) && file_exists($exampleFile)) {
        copy($exampleFile, $configFile);
        echo "Created config.php from example. Please update with your database settings.\n";
    }
}

// Run auto-setup
autoInstallComposer();
autoCreateConfig();

// Configure session settings based on environment
if ($_SERVER['HTTP_HOST'] === 'localhost:8081' || $_SERVER['HTTP_HOST'] === 'localhost') {
    // For localhost, use default session settings that work with HTTP
    ini_set('session.cookie_secure', '0');
    ini_set('session.cookie_samesite', 'Lax');
}

session_start();

// Load configuration
$config = require_once 'config.php';

// Validate configuration
function validateConfig($config) {
    $required = ['host', 'database', 'username', 'password'];
    $missing = [];
    
    foreach ($required as $key) {
        if (!isset($config[$key]) || empty($config[$key]) || $config[$key] === 'your_password_here') {
            $missing[] = $key;
        }
    }
    
    if (!empty($missing)) {
        http_response_code(500);
        echo json_encode([
            'success' => false, 
            'error' => 'Configuration incomplete. Please update config.php with your database settings.',
            'missing_fields' => $missing,
            'setup_required' => true
        ]);
        exit;
    }
}

// Check configuration before proceeding
validateConfig($config);

// Set JSON response header
header('Content-Type: application/json');

// Database connection
function getDB() {
    global $config;
    try {
        $dsn = "mysql:host={$config['host']};dbname={$config['database']};charset=utf8mb4";
        $pdo = new PDO(
            $dsn,
            $config['username'],
            $config['password'],
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]
        );
        return $pdo;
    } catch (PDOException $e) {
        http_response_code(500);
        
        // Provide more specific error messages
        $errorMsg = 'Database connection failed';
        
        if (strpos($e->getMessage(), 'Unknown database') !== false) {
            $errorMsg = "Database '{$config['database']}' does not exist. Please create it first.";
        } elseif (strpos($e->getMessage(), 'Access denied') !== false) {
            $errorMsg = "Database access denied. Check username/password in config.php";
        } elseif (strpos($e->getMessage(), "Can't connect") !== false) {
            $errorMsg = "Cannot connect to database server '{$config['host']}'. Is it running?";
        }
        
        echo json_encode([
            'success' => false, 
            'error' => $errorMsg,
            'details' => $e->getMessage(),
            'setup_required' => true
        ]);
        exit;
    }
}

// Utility functions
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    // Add proper padding
    $padding = 4 - (strlen($data) % 4);
    if ($padding !== 4) {
        $data .= str_repeat('=', $padding);
    }
    
    // Convert base64url to base64 and decode
    return base64_decode(strtr($data, '-_', '+/'));
}

// Generate secure random bytes
function generateChallenge($length = 32) {
    return random_bytes($length);
}

// Handle different actions
$action = $_GET['action'] ?? $_POST['action'] ?? '';

switch ($action) {
    case 'register_begin':
        handleRegisterBegin();
        break;
    case 'register_complete':
        handleRegisterComplete();
        break;
    case 'login_begin':
        handleLoginBegin();
        break;
    case 'login_complete':
        handleLoginComplete();
        break;
    case 'get_user':
        handleGetUser();
        break;
    case 'logout':
        handleLogout();
        break;
    default:
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid action']);
}

function handleRegisterBegin() {
    global $config;
    
    $input = json_decode(file_get_contents('php://input'), true);
    $email = $input['email'] ?? '';
    $displayName = $input['displayName'] ?? '';
    
    if (!$email || !$displayName) {
        echo json_encode(['success' => false, 'error' => 'Email and display name required']);
        return;
    }
    
    // Check if user already exists
    $db = getDB();
    $stmt = $db->prepare('SELECT id FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    
    if ($user) {
        echo json_encode(['success' => false, 'error' => 'User already exists']);
        return;
    }
    
    // Generate challenge
    $challenge = generateChallenge();
    $_SESSION['registration_challenge'] = base64url_encode($challenge);
    $_SESSION['registration_email'] = $email;
    $_SESSION['registration_display_name'] = $displayName;
    
    // Generate user ID
    $userId = random_bytes(32);
    $_SESSION['registration_user_id'] = base64url_encode($userId);
    
    // Debug session data
    error_log('Session data in register_begin: ' . print_r($_SESSION, true));
    error_log('Session ID: ' . session_id());
    
    $options = [
        'challenge' => $_SESSION['registration_challenge'],
        'rp' => [
            'name' => $config['rp_name'],
            'id' => $config['rp_id']
        ],
        'user' => [
            'id' => $_SESSION['registration_user_id'],
            'name' => $email,
            'displayName' => $displayName
        ],
        'pubKeyCredParams' => [
            ['type' => 'public-key', 'alg' => -7], // ES256
            ['type' => 'public-key', 'alg' => -257] // RS256
        ],
        'timeout' => $config['timeout'],
        'attestation' => 'none',
        'authenticatorSelection' => [
            'userVerification' => $config['user_verification']
        ]
    ];
    
    echo json_encode(['success' => true, 'options' => $options]);
}

function handleRegisterComplete() {
    try {
        $input = json_decode(file_get_contents('php://input'), true);
        
        // Debug session data
        error_log('Session data in register_complete: ' . print_r($_SESSION, true));
        
        if (!isset($_SESSION['registration_challenge'])) {
            echo json_encode(['success' => false, 'error' => 'No registration in progress', 'session_id' => session_id()]);
            return;
        }
        
        $credential = $input['credential'] ?? null;
        if (!$credential) {
            echo json_encode(['success' => false, 'error' => 'No credential provided']);
            return;
        }
        
        // Basic validation (in production, you'd do proper attestation verification)
        try {
            $clientDataJSON = base64url_decode($credential['response']['clientDataJSON']);
            if ($clientDataJSON === false) {
                throw new Exception('Failed to decode clientDataJSON');
            }
            
            $clientData = json_decode($clientDataJSON, true);
            if ($clientData === null) {
                throw new Exception('Failed to parse clientDataJSON as JSON');
            }
        } catch (Exception $e) {
            echo json_encode([
                'success' => false, 
                'error' => 'Invalid clientDataJSON: ' . $e->getMessage(),
                'debug' => [
                    'input_length' => strlen($credential['response']['clientDataJSON']),
                    'input_sample' => substr($credential['response']['clientDataJSON'], 0, 50)
                ]
            ]);
            return;
        }
        
        // Verify challenge
        if ($clientData['challenge'] !== $_SESSION['registration_challenge']) {
            echo json_encode(['success' => false, 'error' => 'Challenge mismatch']);
            return;
        }
        
        // Verify origin
        $expectedOrigin = 'https://' . $_SERVER['HTTP_HOST'];
        if ($_SERVER['HTTP_HOST'] === 'localhost:8081' || strpos($_SERVER['HTTP_HOST'], 'localhost:') === 0) {
            $expectedOrigin = 'http://' . $_SERVER['HTTP_HOST'];
        }
        
        if ($clientData['origin'] !== $expectedOrigin) {
            echo json_encode(['success' => false, 'error' => 'Origin mismatch']);
            return;
        }
        
        // Extract public key (simplified - in production use proper CBOR parsing)
        try {
            $attestationObject = base64url_decode($credential['response']['attestationObject']);
            if ($attestationObject === false) {
                throw new Exception('Failed to decode attestationObject');
            }
        } catch (Exception $e) {
            echo json_encode(['success' => false, 'error' => 'Invalid attestationObject: ' . $e->getMessage()]);
            return;
        }
        
        // For now, just store the credential ID and a placeholder public key
        $credentialId = $credential['id'];
        $publicKey = base64_encode($attestationObject); // Simplified storage
        
        // Save user and credential
        $db = getDB();
        $db->beginTransaction();
        
        try {
            // Insert user
            error_log('Inserting user: ' . $_SESSION['registration_email'] . ' / ' . $_SESSION['registration_display_name']);
            $stmt = $db->prepare('INSERT INTO users (email, display_name) VALUES (?, ?)');
            $stmt->execute([$_SESSION['registration_email'], $_SESSION['registration_display_name']]);
            $userId = $db->lastInsertId();
            error_log('User inserted with ID: ' . $userId);
            
            // Insert credential
            error_log('Inserting credential for user ID: ' . $userId);
            $stmt = $db->prepare('INSERT INTO passkey_credentials (user_id, credential_id, public_key) VALUES (?, ?, ?)');
            $stmt->execute([$userId, $credentialId, $publicKey]);
            error_log('Credential inserted successfully');
            
            $db->commit();
            error_log('Database transaction committed');
            
            // Set logged in session before cleaning up
            $_SESSION['user_id'] = $userId;
            $_SESSION['user_email'] = $_SESSION['registration_email'];
            
            // Clean up session
            unset($_SESSION['registration_challenge']);
            unset($_SESSION['registration_email']);
            unset($_SESSION['registration_display_name']);
            unset($_SESSION['registration_user_id']);
            
            echo json_encode(['success' => true, 'message' => 'Registration successful']);
            
        } catch (Exception $e) {
            $db->rollback();
            error_log('Database error in registration: ' . $e->getMessage());
            echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
        }
        
    } catch (Exception $e) {
        error_log('General error in handleRegisterComplete: ' . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Server error: ' . $e->getMessage()]);
    }
}

function handleLoginBegin() {
    global $config;
    
    // Generate challenge
    $challenge = generateChallenge();
    $_SESSION['login_challenge'] = base64url_encode($challenge);
    
    // Get all available credentials for this site
    $db = getDB();
    $stmt = $db->prepare('SELECT credential_id FROM passkey_credentials');
    $stmt->execute();
    $credentials = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    // Format credentials for WebAuthn
    $allowCredentials = [];
    foreach ($credentials as $credentialId) {
        $allowCredentials[] = [
            'type' => 'public-key',
            'id' => $credentialId,
            'transports' => ['internal', 'hybrid', 'usb', 'nfc', 'ble'] // Support all transport methods
        ];
    }
    
    $options = [
        'challenge' => $_SESSION['login_challenge'],
        'rpId' => $config['rp_id'],
        'timeout' => $config['timeout'],
        'userVerification' => $config['user_verification'],
        'allowCredentials' => $allowCredentials
    ];
    
    error_log('Login options: ' . json_encode($options));
    error_log('Found ' . count($allowCredentials) . ' credentials for login');
    
    echo json_encode(['success' => true, 'options' => $options]);
}

function handleLoginComplete() {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($_SESSION['login_challenge'])) {
        echo json_encode(['success' => false, 'error' => 'No login in progress']);
        return;
    }
    
    $credential = $input['credential'] ?? null;
    if (!$credential) {
        echo json_encode(['success' => false, 'error' => 'No credential provided']);
        return;
    }
    
    // Look up credential
    $db = getDB();
    $stmt = $db->prepare('
        SELECT c.user_id, c.public_key, c.sign_count, u.email, u.display_name 
        FROM passkey_credentials c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.credential_id = ?
    ');
    $stmt->execute([$credential['id']]);
    $credentialRecord = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$credentialRecord) {
        echo json_encode(['success' => false, 'error' => 'Credential not found']);
        return;
    }
    
    // Basic validation (in production, you'd do proper signature verification)
    $clientDataJSON = base64url_decode($credential['response']['clientDataJSON']);
    $clientData = json_decode($clientDataJSON, true);
    
    // Verify challenge
    if ($clientData['challenge'] !== $_SESSION['login_challenge']) {
        echo json_encode(['success' => false, 'error' => 'Challenge mismatch']);
        return;
    }
    
    // Verify origin
    $expectedOrigin = 'https://' . $_SERVER['HTTP_HOST'];
    if ($_SERVER['HTTP_HOST'] === 'localhost' || strpos($_SERVER['HTTP_HOST'], 'localhost:') === 0) {
        $expectedOrigin = 'http://' . $_SERVER['HTTP_HOST'];
    }
    
    if ($clientData['origin'] !== $expectedOrigin) {
        echo json_encode(['success' => false, 'error' => 'Origin mismatch']);
        return;
    }
    
    // Update sign count (simplified)
    $stmt = $db->prepare('UPDATE passkey_credentials SET last_used = NOW() WHERE credential_id = ?');
    $stmt->execute([$credential['id']]);
    
    // Set session
    $_SESSION['user_id'] = $credentialRecord['user_id'];
    $_SESSION['user_email'] = $credentialRecord['email'];
    
    // Clean up
    unset($_SESSION['login_challenge']);
    
    echo json_encode([
        'success' => true, 
        'user' => [
            'id' => $credentialRecord['user_id'],
            'email' => $credentialRecord['email'],
            'displayName' => $credentialRecord['display_name']
        ]
    ]);
}

function handleGetUser() {
    if (isset($_SESSION['user_id'])) {
        $db = getDB();
        $stmt = $db->prepare('SELECT id, email, display_name FROM users WHERE id = ?');
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            echo json_encode(['success' => true, 'user' => $user]);
        } else {
            echo json_encode(['success' => false, 'error' => 'User not found']);
        }
    } else {
        echo json_encode(['success' => false, 'error' => 'Not logged in']);
    }
}

function handleLogout() {
    // Clear the session
    session_destroy();
    
    // Send success response
    echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
}
?>
