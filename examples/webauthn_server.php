<?php
/**
 * Standalone WebAuthn Authentication Server
 * 
 * This file implements proper server-side WebAuthn verification using the
 * web-auth/webauthn-lib library with auto-installation via Composer.
 * 
 * Similar to passkey.php, this will automatically install dependencies.
 */

// Error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Auto-install WebAuthn library if not present
function autoInstallWebAuthn() {
    $vendorDir = __DIR__ . '/vendor';
    $composerJson = __DIR__ . '/composer.json';
    $webauthnLibPath = $vendorDir . '/web-auth/webauthn-lib';
    
    // Check if WebAuthn library is already installed
    if (file_exists($webauthnLibPath)) {
        return true;
    }
    
    echo "Installing WebAuthn library...\n";
    
    // Create composer.json if it doesn't exist
    if (!file_exists($composerJson)) {
        $composerConfig = [
            "require" => [
                "web-auth/webauthn-lib" => "^4.0",
                "ramsey/uuid" => "^4.0",
                "nyholm/psr7" => "^1.5",
                "symfony/http-foundation" => "^6.0|^7.0"
            ],
            "config" => [
                "platform" => [
                    "php" => "7.4"
                ]
            ]
        ];
        
        file_put_contents($composerJson, json_encode($composerConfig, JSON_PRETTY_PRINT));
        echo "Created composer.json\n";
    }
    
    // Check if composer is available
    $composerCommand = 'composer';
    $composerPhar = __DIR__ . '/composer.phar';
    
    // Try to use local composer.phar first
    if (file_exists($composerPhar)) {
        $composerCommand = "php $composerPhar";
    } else {
        // Check if global composer is available
        exec('which composer 2>/dev/null', $output, $returnCode);
        if ($returnCode !== 0) {
            // Download composer.phar
            echo "Downloading Composer...\n";
            $composerInstaller = file_get_contents('https://getcomposer.org/installer');
            if ($composerInstaller === false) {
                throw new Exception('Failed to download Composer installer');
            }
            
            file_put_contents(__DIR__ . '/composer-setup.php', $composerInstaller);
            
            // Install composer
            exec('php composer-setup.php --install-dir=' . __DIR__ . ' --filename=composer.phar 2>&1', $output, $returnCode);
            unlink(__DIR__ . '/composer-setup.php');
            
            if ($returnCode !== 0) {
                throw new Exception('Failed to install Composer: ' . implode("\n", $output));
            }
            
            $composerCommand = "php $composerPhar";
        }
    }
    
    // Install dependencies
    echo "Installing WebAuthn dependencies...\n";
    exec("cd " . __DIR__ . " && $composerCommand install --no-dev --optimize-autoloader 2>&1", $output, $returnCode);
    
    if ($returnCode !== 0) {
        throw new Exception('Failed to install WebAuthn library: ' . implode("\n", $output));
    }
    
    if (!file_exists($webauthnLibPath)) {
        throw new Exception('WebAuthn library installation failed - library not found after installation');
    }
    
    echo "WebAuthn library installed successfully!\n";
    return true;
}

// Try to auto-install WebAuthn library
try {
    autoInstallWebAuthn();
} catch (Exception $e) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => 'Failed to install WebAuthn library: ' . $e->getMessage(),
        'note' => 'Please install manually: composer require web-auth/webauthn-lib'
    ]);
    exit;
}

// Load the auto-installed WebAuthn library
$autoloader = __DIR__ . '/vendor/autoload.php';
if (!file_exists($autoloader)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => 'WebAuthn library not found after installation',
        'note' => 'Please install manually: composer require web-auth/webauthn-lib'
    ]);
    exit;
}

require_once $autoloader;

use Webauthn\Server;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialParametersCollection;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialDescriptorCollection;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\AttestedCredentialData;
use Ramsey\Uuid\Uuid;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Component\HttpFoundation\Request;

// Load configuration
$configFile = __DIR__ . '/config.php';
if (!file_exists($configFile)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Configuration file not found. Copy config.example.php to config.php and configure it.']);
    exit;
}

$config = require $configFile;

// Handle both array config and constants
if (is_array($config)) {
    $amemberUrl = $config['amember_base_url'];
    $apiKey = $config['api_key'];
    $rpId = $config['rp_id'] ?? 'localhost';
    $rpName = $config['rp_name'] ?? 'WebAuthn Server';
} else {
    $amemberUrl = defined('AMEMBER_URL') ? AMEMBER_URL : '';
    $apiKey = defined('AMEMBER_API_KEY') ? AMEMBER_API_KEY : '';
    $rpId = 'localhost';
    $rpName = 'WebAuthn Server';
}

// CORS Headers
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
header('Content-Type: application/json');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit;
}

/**
 * Simple credential repository implementation
 */
class SimpleCredentialRepository implements PublicKeyCredentialSourceRepository
{
    private $credentials = [];
    private $amemberUrl;
    private $apiKey;
    
    public function __construct($amemberUrl, $apiKey) {
        $this->amemberUrl = $amemberUrl;
        $this->apiKey = $apiKey;
        $this->loadCredentialsFromAmember();
    }
    
    private function loadCredentialsFromAmember() {
        // Get credentials from aMember API
        $endpoints = [
            '/api/passkey/credentials',
            '/misc/passkey?action=get-credentials'
        ];
        
        foreach ($endpoints as $endpoint) {
            $url = rtrim($this->amemberUrl, '/') . $endpoint;
            
            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'header' => [
                        'X-API-KEY: ' . $this->apiKey,
                        'Content-Type: application/json'
                    ]
                ]
            ]);
            
            $response = @file_get_contents($url, false, $context);
            if ($response !== false) {
                $data = json_decode($response, true);
                if (isset($data['ok']) && $data['ok'] && isset($data['credentials'])) {
                    foreach ($data['credentials'] as $cred) {
                        if (isset($cred['id'])) {
                            // Create a PublicKeyCredentialSource from aMember credential
                            $credentialSource = new PublicKeyCredentialSource(
                                $cred['id'],
                                'public-key',
                                [],
                                new AttestedCredentialData(
                                    '',
                                    '',
                                    $cred['id'],
                                    null,
                                    0,
                                    0
                                ),
                                new EmptyTrustPath(),
                                Uuid::uuid4(),
                                base64_decode($cred['publicKey'] ?? ''),
                                $cred['userHandle'] ?? '',
                                0
                            );
                            
                            $this->credentials[] = $credentialSource;
                        }
                    }
                    break;
                }
            }
        }
    }
    
    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        foreach ($this->credentials as $credential) {
            if ($credential->getPublicKeyCredentialId() === $publicKeyCredentialId) {
                return $credential;
            }
        }
        return null;
    }
    
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        $userCredentials = [];
        foreach ($this->credentials as $credential) {
            if ($credential->getUserHandle() === $publicKeyCredentialUserEntity->getId()) {
                $userCredentials[] = $credential;
            }
        }
        return $userCredentials;
    }
    
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $this->credentials[] = $publicKeyCredentialSource;
    }
    
    public function getAllCredentials(): array
    {
        return $this->credentials;
    }
}

// Initialize WebAuthn components
$rpEntity = new PublicKeyCredentialRpEntity($rpName, $rpId);
$credentialRepository = new SimpleCredentialRepository($amemberUrl, $apiKey);

// Create PSR-7 factory for HTTP messages
$psr17Factory = new Psr17Factory();

// Handle different actions
// Set REQUEST_METHOD if not set (for command line testing)
if (!isset($_SERVER['REQUEST_METHOD'])) {
    $_SERVER['REQUEST_METHOD'] = 'GET';
}

// Get action from request
$action = $_GET['action'] ?? $_POST['action'] ?? 'challenge';

switch ($action) {
    case 'challenge':
        // Generate authentication challenge
        try {
            $credentials = $credentialRepository->getAllCredentials();
            $allowCredentials = new PublicKeyCredentialDescriptorCollection();
            
            foreach ($credentials as $credential) {
                $allowCredentials->add(new PublicKeyCredentialDescriptor(
                    'public-key',
                    $credential->getPublicKeyCredentialId()
                ));
            }
            
            $challenge = random_bytes(32);
            $options = new PublicKeyCredentialRequestOptions(
                $challenge,
                60000, // 60 seconds timeout
                $rpId,
                $allowCredentials
            );
            
            // Store challenge in session for later verification
            session_start();
            $_SESSION['webauthn_challenge'] = base64_encode($challenge);
            
            echo json_encode([
                'success' => true,
                'options' => [
                    'challenge' => base64url_encode($challenge),
                    'timeout' => 60000,
                    'rpId' => $rpId,
                    'allowCredentials' => array_map(function($cred) {
                        return [
                            'type' => 'public-key',
                            'id' => base64url_encode($cred->getPublicKeyCredentialId())
                        ];
                    }, $credentials),
                    'userVerification' => 'preferred'
                ]
            ]);
            
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => 'Failed to generate challenge: ' . $e->getMessage()
            ]);
        }
        break;
        
    case 'verify':
        // Verify authentication
        try {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                throw new Exception('POST method required');
            }
            
            $input = json_decode(file_get_contents('php://input'), true);
            if (!isset($input['credential'])) {
                throw new Exception('Credential data required');
            }
            
            session_start();
            if (!isset($_SESSION['webauthn_challenge'])) {
                throw new Exception('No challenge found in session');
            }
            
            $challenge = base64_decode($_SESSION['webauthn_challenge']);
            unset($_SESSION['webauthn_challenge']);
            
            // Load and verify the credential
            $loader = new PublicKeyCredentialLoader();
            
            // Convert the credential data
            $credentialData = $input['credential'];
            $credentialJson = json_encode([
                'id' => $credentialData['id'],
                'rawId' => $credentialData['rawId'],
                'type' => $credentialData['type'],
                'response' => [
                    'clientDataJSON' => $credentialData['response']['clientDataJSON'],
                    'authenticatorData' => $credentialData['response']['authenticatorData'],
                    'signature' => $credentialData['response']['signature'],
                    'userHandle' => $credentialData['response']['userHandle']
                ]
            ]);
            
            $publicKeyCredential = $loader->load($credentialJson);
            $authenticatorAssertionResponse = $publicKeyCredential->getResponse();
            
            if (!$authenticatorAssertionResponse instanceof AuthenticatorAssertionResponse) {
                throw new Exception('Invalid response type');
            }
            
            // Create validator and verify
            $validator = new AuthenticatorAssertionResponseValidator(
                $credentialRepository,
                null,
                [],
                null
            );
            
            $request = Request::createFromGlobals();
            $psr7Request = $psr17Factory->createServerRequest(
                $request->getMethod(),
                $request->getUri()
            );
            
            $options = new PublicKeyCredentialRequestOptions(
                $challenge,
                60000,
                $rpId,
                new PublicKeyCredentialDescriptorCollection(),
                'preferred',
                []
            );
            
            $credentialSource = $validator->check(
                $publicKeyCredential->getRawId(),
                $authenticatorAssertionResponse,
                $options,
                $psr7Request,
                null
            );
            
            // Authentication successful - check access with aMember
            $accessResult = checkAmemberAccess($credentialSource, $amemberUrl, $apiKey);
            
            echo json_encode([
                'ok' => true,
                'access' => true,
                'user_id' => $accessResult['user_id'] ?? 'unknown',
                'name' => $accessResult['name'] ?? 'Unknown User',
                'email' => $accessResult['email'] ?? 'unknown@example.com'
            ]);
            
        } catch (Exception $e) {
            http_response_code(400);
            echo json_encode([
                'ok' => false,
                'error' => 'Authentication failed: ' . $e->getMessage()
            ]);
        }
        break;
        
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
}

/**
 * Check access with aMember API
 */
function checkAmemberAccess($credentialSource, $amemberUrl, $apiKey) {
    // This would integrate with your aMember API to verify user access
    // For now, return a simple success response
    return [
        'user_id' => 1,
        'name' => 'Test User',
        'email' => 'test@example.com',
        'access' => true
    ];
}

/**
 * Base64url encode
 */
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Base64url decode
 */
function base64url_decode($data) {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}
?>
