<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn Cross-Domain Debug</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
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
            margin: 10px 5px;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #0056CC;
        }
        .output {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 20px;
            margin: 20px 0;
            white-space: pre-wrap;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 14px;
            max-height: 400px;
            overflow-y: auto;
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
        <h1>🔍 Cross-Domain Debug Test</h1>
        
        <div class="warning">
            <strong>Purpose:</strong> Minimal test to isolate cross-domain WebAuthn issues without our complex client code.
        </div>
        
        <p>Current domain: <strong><?= $_SERVER['HTTP_HOST'] ?></strong></p>
        
        <button id="testMinimal" class="btn">Test Minimal Cross-Domain</button>
        <button id="testLocalChallenge" class="btn">Test With Local Challenge</button>
        <button id="testWellKnown" class="btn">Verify Well-Known File</button>
        <button id="testCORS" class="btn">Test CORS Headers</button>
        
        <div id="output" class="output">Click a button above to run tests...</div>
    </div>

    <script>
        const output = document.getElementById('output');
        
        function log(message) {
            output.textContent += new Date().toISOString() + ': ' + message + '\n';
            output.scrollTop = output.scrollHeight;
        }
        
        function clearOutput() {
            output.textContent = '';
        }
        
        // Minimal cross-domain test with hardcoded challenge
        async function testMinimalCrossDomain() {
            clearOutput();
            log('Testing minimal cross-domain WebAuthn...');
            log('This bypasses our server entirely to isolate the issue');
            
            try {
                // Create a simple challenge
                const challenge = new Uint8Array(32);
                crypto.getRandomValues(challenge);
                
                const options = {
                    challenge: challenge,
                    rpId: 'kumpeapps.com',
                    timeout: 30000,
                    userVerification: 'preferred'
                };
                
                log('Testing with hardcoded options:');
                log(`RP ID: ${options.rpId}`);
                log(`Current origin: ${window.location.origin}`);
                log(`Timeout: ${options.timeout}ms`);
                
                log('Calling navigator.credentials.get()...');
                
                const credential = await navigator.credentials.get({
                    publicKey: options
                });
                
                if (credential) {
                    log('✅ SUCCESS: Cross-domain WebAuthn is working!');
                    log(`Credential ID: ${credential.id}`);
                    log('This means the issue is in our server code, not the browser setup');
                } else {
                    log('❌ No credential returned');
                }
                
            } catch (error) {
                log(`❌ FAILED: ${error.name}: ${error.message}`);
                
                if (error.name === 'SecurityError') {
                    log('SecurityError indicates Related Origins or CORS issue');
                } else if (error.name === 'AbortError') {
                    log('AbortError indicates authenticator or timeout issue');
                } else if (error.name === 'NotAllowedError') {
                    log('NotAllowedError indicates no credentials or user cancelled');
                }
                
                log('\nPossible causes:');
                log('1. .well-known/webauthn file missing or incorrect');
                log('2. CORS headers blocking the request');
                log('3. Browser policy change');
                log('4. No credentials exist for kumpeapps.com');
            }
        }
        
        // Test with our server challenge
        async function testWithLocalChallenge() {
            clearOutput();
            log('Testing with server-generated challenge...');
            
            try {
                log('Fetching challenge from server...');
                const response = await fetch('webauthn_simple.php?action=challenge', {
                    credentials: 'include'
                });
                
                if (!response.ok) {
                    throw new Error(`Server returned ${response.status}`);
                }
                
                const data = await response.json();
                log(`Server response: ${JSON.stringify(data, null, 2)}`);
                
                if (!data.success) {
                    throw new Error(`Server error: ${data.error}`);
                }
                
                // Convert challenge
                const options = data.options;
                options.challenge = base64urlToArrayBuffer(options.challenge);
                
                log(`Using server RP ID: ${options.rpId}`);
                log('Attempting WebAuthn with server challenge...');
                
                const credential = await navigator.credentials.get({
                    publicKey: options
                });
                
                if (credential) {
                    log('✅ SUCCESS: Server challenge works!');
                    log('Issue is likely in our client JavaScript logic');
                } else {
                    log('❌ No credential with server challenge');
                }
                
            } catch (error) {
                log(`❌ Server challenge failed: ${error.name}: ${error.message}`);
                
                if (error.message.includes('Server returned')) {
                    log('Server communication issue - check CORS headers');
                } else {
                    log('WebAuthn API issue - same as minimal test');
                }
            }
        }
        
        // Verify well-known file
        async function testWellKnownFile() {
            clearOutput();
            log('Verifying .well-known/webauthn file...');
            
            try {
                const response = await fetch('https://www.kumpeapps.com/.well-known/webauthn', {
                    cache: 'no-cache'
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                
                const data = await response.json();
                log('Well-known file contents:');
                log(JSON.stringify(data, null, 2));
                
                const currentOrigin = window.location.origin;
                const isAuthorized = data.origins && data.origins.includes(currentOrigin);
                
                log(`Current origin: ${currentOrigin}`);
                log(`Is authorized: ${isAuthorized}`);
                
                if (!isAuthorized) {
                    log('❌ PROBLEM: Current origin not in well-known file!');
                } else {
                    log('✅ Well-known file is correct');
                }
                
            } catch (error) {
                log(`❌ Well-known file error: ${error.message}`);
                log('This could be the cause of cross-domain failures');
            }
        }
        
        // Test CORS headers
        async function testCORSHeaders() {
            clearOutput();
            log('Testing CORS headers...');
            
            try {
                const response = await fetch('webauthn_simple.php?action=challenge', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Origin': window.location.origin
                    }
                });
                
                log('Response headers:');
                for (let [key, value] of response.headers.entries()) {
                    if (key.toLowerCase().includes('access-control')) {
                        log(`${key}: ${value}`);
                    }
                }
                
                log(`Response status: ${response.status}`);
                log(`Response ok: ${response.ok}`);
                
                if (response.ok) {
                    log('✅ CORS headers appear to be working');
                } else {
                    log('❌ CORS issue detected');
                }
                
            } catch (error) {
                log(`❌ CORS test failed: ${error.message}`);
            }
        }
        
        // Utility function
        function base64urlToArrayBuffer(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(base64url.length + (4 - base64url.length % 4) % 4, '=');
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }
        
        // Event listeners
        document.getElementById('testMinimal').addEventListener('click', testMinimalCrossDomain);
        document.getElementById('testLocalChallenge').addEventListener('click', testWithLocalChallenge);
        document.getElementById('testWellKnown').addEventListener('click', testWellKnownFile);
        document.getElementById('testCORS').addEventListener('click', testCORSHeaders);
        
        // Initial info
        log('Cross-Domain Debug Tool Ready');
        log(`Current domain: ${window.location.hostname}`);
        log(`Browser: ${navigator.userAgent}`);
        log('Click buttons above to isolate the issue...');
    </script>
</body>
</html>
