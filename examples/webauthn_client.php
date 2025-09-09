<?php
// Load config - REQUIRED
if (!file_exists('config.php')) {
    $error = 'Configuration file config.php not found. Please copy config.example.php to config.php and configure it.';
} else {
    $config = include 'config.php';
    
    // Validate required config
    $required = ['amember_base_url', 'api_key'];
    $missing = [];
    foreach ($required as $key) {
        if (empty($config[$key]) || $config[$key] === 'YOUR_API_KEY_HERE' || $config[$key] === 'YOUR_AMEMBER_URL_HERE') {
            $missing[] = $key;
        }
    }
    
    if (!empty($missing)) {
        $error = 'Missing required configuration: ' . implode(', ', $missing) . '. Please update config.php with your actual values.';
    }
}

if (isset($error)) {
    ?>
    <!DOCTYPE html>
    <html><head><title>Configuration Error</title></head>
    <body style="font-family: Arial; margin: 50px; background: #ffe6e6;">
        <div style="background: white; padding: 30px; border-radius: 8px; border: 2px solid #ff6b6b;">
            <h1 style="color: #d63031;">⚠️ Configuration Required</h1>
            <p style="color: #333; font-size: 16px;"><?= htmlspecialchars($error) ?></p>
            <h3>Required Configuration:</h3>
            <ul>
                <li><code>amember_base_url</code> - Your aMember installation URL</li>
                <li><code>api_key</code> - Your aMember API key</li>
            </ul>
            <p><em>Note: RP ID and RP Name will be automatically retrieved from aMember configuration.</em></p>
        </div>
    </body></html>
    <?php
    exit;
}

$amemberUrl = rtrim($config['amember_base_url'], '/');

// Get RP configuration from aMember (or fallback)
function getAmemberConfig($amemberUrl, $apiKey) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $amemberUrl . '/api/misc/passkey');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        '_key' => $apiKey,
        'action' => 'get-config'
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode === 200 && $response) {
        $data = json_decode($response, true);
        if ($data && isset($data['config'])) {
            return [
                'rp_id' => $data['config']['rp_id'] ?? parse_url($amemberUrl, PHP_URL_HOST),
                'rp_name' => $data['config']['rp_name'] ?? 'aMember Site'
            ];
        }
    }
    
    // Fallback to extracting from URL
    $parsedUrl = parse_url($amemberUrl);
    $host = $parsedUrl['host'] ?? 'localhost';
    $rpId = preg_replace('/^www\./', '', $host);
    
    return [
        'rp_id' => $rpId,
        'rp_name' => 'aMember Site'
    ];
}

$amemberConfig = getAmemberConfig($amemberUrl, $config['api_key']);
$rpId = $amemberConfig['rp_id'];
$rpName = $amemberConfig['rp_name'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn Authentication</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            margin: 20px 0;
            transition: all 0.3s ease;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        .status {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            text-align: center;
        }
        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .status.info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        .user-info {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
            display: none;
        }
        .config-info {
            font-size: 12px;
            color: #666;
            margin-bottom: 20px;
            padding: 10px;
            background: #f0f0f0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 WebAuthn Authentication</h1>
        
        <div class="config-info">
            <strong>Configuration:</strong><br>
            RP ID: <?= htmlspecialchars($rpId) ?><br>
            aMember URL: <?= htmlspecialchars($amemberUrl) ?><br>
            Server: webauthn_simple.php
        </div>
        
        <div id="status"></div>
        
        <button id="authButton" class="btn">
            🔑 Authenticate with Passkey
        </button>
        
        <div id="user-info" class="user-info"></div>
    </div>

    <script>
        const statusDiv = document.getElementById('status');
        const authButton = document.getElementById('authButton');
        const userInfoDiv = document.getElementById('user-info');

        function showStatus(message, type = 'info') {
            statusDiv.innerHTML = message;
            statusDiv.className = `status ${type}`;
        }

        function base64urlToArrayBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(base64url.length + (4 - base64url.length % 4) % 4, '=');
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }

        function arrayBufferToBase64url(buffer) {
            const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        function displayUserInfo(userData) {
            userInfoDiv.innerHTML = `
                <h3>✅ Authentication Successful!</h3>
                <div class="user-details">
                    <p><strong>User ID:</strong> ${userData.user_id || 'N/A'}</p>
                    <p><strong>Name:</strong> ${userData.name || 'N/A'}</p>
                    <p><strong>Email:</strong> ${userData.email || 'N/A'}</p>
                    <p><strong>Access:</strong> ${userData.access ? 'Granted' : 'Denied'}</p>
                </div>
            `;
            userInfoDiv.style.display = 'block';
        }

        async function authenticateWithPasskey() {
            try {
                showStatus('Getting challenge from server...', 'info');
                authButton.disabled = true;

                // Get challenge from simple WebAuthn server
                const challengeResponse = await fetch('webauthn_simple.php?action=challenge', {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                });

                if (!challengeResponse.ok) {
                    throw new Error(`Challenge request failed: ${challengeResponse.status}`);
                }

                const challengeData = await challengeResponse.json();
                console.log('Challenge received:', challengeData);

                if (!challengeData.success) {
                    throw new Error(challengeData.error || 'Failed to get challenge');
                }

                // Convert challenge and credential IDs to ArrayBuffers
                const options = challengeData.options;
                options.challenge = base64urlToArrayBuffer(options.challenge);
                
                if (options.allowCredentials) {
                    options.allowCredentials = options.allowCredentials.map(cred => ({
                        ...cred,
                        id: base64urlToArrayBuffer(cred.id)
                    }));
                }

                console.log('Converted options:', options);
                showStatus('Please authenticate with your passkey...', 'info');

                // Perform WebAuthn authentication
                const credential = await navigator.credentials.get({
                    publicKey: options
                });

                if (!credential) {
                    throw new Error('No credential received from authenticator');
                }

                console.log('Credential received:', credential.id);
                showStatus('Verifying with server...', 'info');

                // Prepare credential data for server
                const credentialData = {
                    id: credential.id,
                    rawId: arrayBufferToBase64url(credential.rawId),
                    type: credential.type,
                    response: {
                        clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
                        authenticatorData: arrayBufferToBase64url(credential.response.authenticatorData),
                        signature: arrayBufferToBase64url(credential.response.signature),
                        userHandle: credential.response.userHandle ? 
                            arrayBufferToBase64url(credential.response.userHandle) : null
                    }
                };

                // Send to server for verification
                const verifyResponse = await fetch('webauthn_simple.php?action=verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        credential: credentialData
                    })
                });

                if (!verifyResponse.ok) {
                    throw new Error(`Verification failed: ${verifyResponse.status}`);
                }

                const verifyData = await verifyResponse.json();
                console.log('Verification result:', verifyData);

                if (verifyData.success) {
                    showStatus('Authentication successful!', 'success');
                    displayUserInfo(verifyData);
                } else {
                    throw new Error(verifyData.error || 'Verification failed');
                }

            } catch (error) {
                console.error('Authentication error:', error);
                showStatus(`Authentication failed: ${error.message}`, 'error');
                userInfoDiv.style.display = 'none';
            } finally {
                authButton.disabled = false;
            }
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Page loaded');
            
            if (!window.PublicKeyCredential) {
                showStatus('WebAuthn not supported in this browser', 'error');
                authButton.disabled = true;
                return;
            }

            authButton.addEventListener('click', authenticateWithPasskey);
            showStatus('Ready for WebAuthn authentication!', 'success');
        });
    </script>
</body>
</html>
