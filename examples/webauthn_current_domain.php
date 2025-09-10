<?php
require_once '../config.php';

// Use current domain instead of cross-domain
$currentDomain = $_SERVER['HTTP_HOST'];
$currentDomain = preg_replace('/^www\./', '', $currentDomain); // Remove www prefix

// Simple configuration for current domain
$config = [
    'rp_id' => $currentDomain,
    'rp_name' => ucfirst($currentDomain) . ' Passkey Auth',
    'amember_url' => $amemberUrl,
    'api_key' => $apiKey
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn - Current Domain Only</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        .btn {
            background: #007AFF;
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            width: 100%;
            margin: 10px 0;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #0056CC;
        }
        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .status {
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
            font-weight: 500;
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
        .warning {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 WebAuthn Authentication - Current Domain</h1>
        
        <div class="config-info">
            <strong>Configuration:</strong><br>
            RP ID: <?= htmlspecialchars($config['rp_id']) ?><br>
            Current Domain: <?= htmlspecialchars($currentDomain) ?><br>
            Mode: Current domain only (no cross-domain)
        </div>
        
        <div class="warning">
            <strong>Note:</strong> This version uses the current domain (<?= htmlspecialchars($currentDomain) ?>) as the RP ID instead of cross-domain authentication. This should work more reliably across all browsers.
        </div>
        
        <div id="status"></div>
        
        <button id="authButton" class="btn">
            🔑 Authenticate with Passkey
        </button>
        
        <div id="user-info" class="user-info"></div>
    </div>

    <script>
        const rpId = '<?= $config['rp_id'] ?>';
        const rpName = '<?= $config['rp_name'] ?>';
        
        console.log('Current domain WebAuthn client loaded');
        console.log('RP ID:', rpId);
        console.log('Current origin:', window.location.origin);
        
        // Base64URL encoding/decoding functions
        function arrayBufferToBase64url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        function base64urlToArrayBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const padding = base64.length % 4;
            const padded = base64 + '='.repeat(padding === 0 ? 0 : 4 - padding);
            const binary = atob(padded);
            const buffer = new ArrayBuffer(binary.length);
            const bytes = new Uint8Array(buffer);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return buffer;
        }

        function showStatus(message, type = 'info') {
            const statusDiv = document.getElementById('status');
            statusDiv.textContent = message;
            statusDiv.className = `status ${type}`;
            statusDiv.style.display = 'block';
        }

        function displayUserInfo(data) {
            const userInfoDiv = document.getElementById('user-info');
            userInfoDiv.innerHTML = `
                <h3>✅ Authentication Successful!</h3>
                <p><strong>User:</strong> ${data.user?.login || 'Unknown'}</p>
                <p><strong>Email:</strong> ${data.user?.email || 'Not provided'}</p>
                <p><strong>Method:</strong> Current domain WebAuthn</p>
                <p><strong>Domain:</strong> ${rpId}</p>
            `;
            userInfoDiv.style.display = 'block';
        }

        async function authenticateWithPasskey() {
            const button = document.getElementById('authButton');
            const userInfoDiv = document.getElementById('user-info');
            
            button.disabled = true;
            userInfoDiv.style.display = 'none';
            showStatus('Requesting authentication challenge...', 'info');

            try {
                // Check WebAuthn support
                if (!window.PublicKeyCredential) {
                    throw new Error('WebAuthn is not supported in this browser');
                }
                
                console.log('Browser info:');
                console.log('User Agent:', navigator.userAgent);
                console.log('WebAuthn supported:', !!window.PublicKeyCredential);
                
                // Get challenge from server
                const challengeResponse = await fetch('webauthn_simple.php?action=challenge', {
                    method: 'GET',
                    credentials: 'same-origin'
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
                let options = challengeData.options;
                
                // Override RP ID to current domain
                options.rpId = rpId;
                options.challenge = base64urlToArrayBuffer(options.challenge);
                
                // Enable discoverable credentials (remove allowCredentials for current domain)
                delete options.allowCredentials;

                console.log('Authentication options:', options);
                console.log('Using current domain RP ID:', options.rpId);

                showStatus('Please use your passkey to authenticate...', 'info');

                // Authenticate with current domain
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

                // Send to server for verification (indicate current domain mode)
                const verifyResponse = await fetch('webauthn_simple.php?action=verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        credential: credentialData,
                        current_domain_mode: true,
                        domain_rp_id: rpId
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
                
                let errorMessage = `Authentication failed: ${error.message}`;
                
                if (error.name === 'NotAllowedError') {
                    errorMessage += '\n\nThis usually means:';
                    errorMessage += '\n- No passkey credentials are available for this domain';
                    errorMessage += '\n- The user cancelled the authentication';
                    errorMessage += '\n\nTo fix this:';
                    errorMessage += `\n- Register a passkey specifically for ${rpId}`;
                    errorMessage += '\n- Make sure your authenticator device is available';
                }
                
                showStatus(errorMessage, 'error');
                userInfoDiv.style.display = 'none';
            } finally {
                button.disabled = false;
            }
        }

        // Event listeners
        document.getElementById('authButton').addEventListener('click', authenticateWithPasskey);
        
        console.log('Current domain WebAuthn client ready');
    </script>
</body>
</html>
