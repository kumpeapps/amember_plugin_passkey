<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn Credential Diagnostics</title>
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
        .btn.danger {
            background: #FF3B30;
        }
        .btn.danger:hover {
            background: #D70015;
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
        <h1>🔍 WebAuthn Credential Diagnostics</h1>
        
        <div class="warning">
            <strong>Purpose:</strong> This tool helps diagnose WebAuthn credential conflicts that might prevent cross-domain authentication from working.
        </div>
        
        <p>Current domain: <strong><?= $_SERVER['HTTP_HOST'] ?></strong></p>
        
        <button id="checkCurrentDomain" class="btn">Check Current Domain Credentials</button>
        <button id="checkCrossDomain" class="btn">Check Cross-Domain (kumpeapps.com)</button>
        <button id="checkConditional" class="btn">Check Conditional UI</button>
        <button id="check1Password" class="btn">Check 1Password Interference</button>
        
        <div class="warning">
            <strong>⚠️ Credential Management:</strong>
            <button id="clearCredentials" class="btn danger">Clear All Credentials (Advanced)</button>
            <p><small>Only use this if you want to remove all WebAuthn credentials from this domain. This action cannot be undone.</small></p>
        </div>
        
        <div id="output" class="output">Click a button above to run diagnostics...</div>
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
        
        async function checkCurrentDomainCredentials() {
            clearOutput();
            log('Checking for credentials on current domain...');
            
            const currentDomain = window.location.hostname.replace(/^www\./, '');
            log(`Current domain RP ID: ${currentDomain}`);
            
            try {
                const challenge = new Uint8Array(32);
                crypto.getRandomValues(challenge);
                
                const options = {
                    challenge: challenge,
                    rpId: currentDomain,
                    timeout: 10000,
                    userVerification: 'preferred'
                };
                
                log('Attempting credential discovery...');
                
                const credential = await navigator.credentials.get({
                    publicKey: options
                });
                
                if (credential) {
                    log('✅ SUCCESS: Found credential on current domain!');
                    log(`Credential ID: ${credential.id}`);
                    log(`Type: ${credential.type}`);
                    log('This explains why cross-domain might not work - there are existing credentials here.');
                } else {
                    log('No credentials found on current domain');
                }
                
            } catch (error) {
                log(`Error: ${error.name}: ${error.message}`);
                if (error.name === 'NotAllowedError') {
                    log('This usually means no credentials exist on this domain.');
                }
            }
        }
        
        async function checkCrossDomainCredentials() {
            clearOutput();
            log('Checking cross-domain credentials (kumpeapps.com)...');
            
            try {
                const challenge = new Uint8Array(32);
                crypto.getRandomValues(challenge);
                
                const options = {
                    challenge: challenge,
                    rpId: 'kumpeapps.com',
                    timeout: 10000,
                    userVerification: 'preferred'
                };
                
                log('Attempting cross-domain credential discovery...');
                
                const credential = await navigator.credentials.get({
                    publicKey: options
                });
                
                if (credential) {
                    log('✅ SUCCESS: Cross-domain WebAuthn is working!');
                    log(`Credential ID: ${credential.id}`);
                    log(`Type: ${credential.type}`);
                } else {
                    log('No cross-domain credentials found');
                }
                
            } catch (error) {
                log(`❌ FAILED: ${error.name}: ${error.message}`);
                if (error.name === 'SecurityError') {
                    log('This confirms Safari is blocking cross-domain WebAuthn.');
                    log('Check: 1) .well-known/webauthn file, 2) CORS headers, 3) Related Origins support');
                }
            }
        }
        
        async function checkConditionalUI() {
            clearOutput();
            log('Checking Conditional UI (AutoFill) support...');
            
            try {
                if (window.PublicKeyCredential && 
                    PublicKeyCredential.isConditionalMediationAvailable) {
                    const available = await PublicKeyCredential.isConditionalMediationAvailable();
                    log(`Conditional mediation available: ${available}`);
                    
                    if (available) {
                        log('This browser supports WebAuthn AutoFill UI');
                    }
                } else {
                    log('Conditional mediation not supported');
                }
            } catch (error) {
                log(`Error checking conditional UI: ${error.message}`);
            }
        }
        
        async function check1PasswordInterference() {
            clearOutput();
            log('Checking for 1Password credential interference...');
            
            const currentDomain = window.location.hostname.replace(/^www\./, '');
            
            // Test 1: Check for credentials with allowCredentials (specific IDs)
            log('Test 1: Checking with specific credential IDs (simulating server response)...');
            try {
                const challenge = new Uint8Array(32);
                crypto.getRandomValues(challenge);
                
                const options = {
                    challenge: challenge,
                    rpId: currentDomain,
                    timeout: 5000,
                    userVerification: 'preferred',
                    allowCredentials: [
                        {
                            type: 'public-key',
                            id: new Uint8Array([1, 2, 3, 4, 5]), // Fake credential ID
                            transports: ['internal', 'usb', 'hybrid']
                        }
                    ]
                };
                
                const credential = await navigator.credentials.get({
                    publicKey: options
                });
                
                log('Unexpected success with fake credential ID - this suggests credential conflicts');
                
            } catch (error) {
                log(`Expected result: ${error.name}: ${error.message}`);
                if (error.name === 'NotAllowedError') {
                    log('✅ Good: No conflicting credentials found with fake ID');
                } else if (error.name === 'AbortError') {
                    log('⚠️ 1Password may be interfering - AbortError suggests authenticator conflicts');
                }
            }
            
            // Test 2: Check cross-domain with short timeout
            log('\nTest 2: Cross-domain test with short timeout...');
            try {
                const challenge = new Uint8Array(32);
                crypto.getRandomValues(challenge);
                
                const options = {
                    challenge: challenge,
                    rpId: 'kumpeapps.com',
                    timeout: 3000, // Short timeout
                    userVerification: 'preferred'
                };
                
                const credential = await navigator.credentials.get({
                    publicKey: options
                });
                
                log('✅ Cross-domain still works!');
                
            } catch (error) {
                log(`❌ Cross-domain failed: ${error.name}: ${error.message}`);
                if (error.name === 'AbortError') {
                    log('🔍 AbortError indicates 1Password or authenticator conflict');
                    log('Recommendation: Check 1Password for saved credentials on this domain');
                }
            }
            
            // Test 3: Platform authenticator availability
            log('\nTest 3: Platform authenticator availability...');
            try {
                if (window.PublicKeyCredential && 
                    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
                    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
                    log(`Platform authenticator available: ${available}`);
                    
                    if (!available) {
                        log('⚠️ Platform authenticator not available - may explain AbortError');
                    }
                }
            } catch (error) {
                log(`Error checking platform authenticator: ${error.message}`);
            }
            
            log('\n📋 1Password Troubleshooting Steps:');
            log('1. Open 1Password app');
            log('2. Look for saved "Passkeys" or "WebAuthn" items');
            log('3. Check if any are associated with this domain');
            log('4. Try temporarily disabling 1Password extension');
            log('5. Test WebAuthn without 1Password running');
        }
        
        async function clearCredentials() {
            if (!confirm('⚠️ WARNING: This will attempt to clear WebAuthn credentials. Continue?')) {
                return;
            }
            
            clearOutput();
            log('⚠️ Credential clearing is not directly supported by WebAuthn API');
            log('To clear credentials:');
            log('1. Safari: Settings > Privacy > Manage Website Data > Remove for this site');
            log('2. Chrome: Settings > Privacy > Site Settings > Additional permissions > WebAuthn credentials');
            log('3. System: Remove from Keychain Access (macOS) or Windows Hello (Windows)');
            log('');
            log('For 1Password: Check 1Password app for saved passkeys');
        }
        
        // Event listeners
        document.getElementById('checkCurrentDomain').addEventListener('click', checkCurrentDomainCredentials);
        document.getElementById('checkCrossDomain').addEventListener('click', checkCrossDomainCredentials);
        document.getElementById('checkConditional').addEventListener('click', checkConditionalUI);
        document.getElementById('check1Password').addEventListener('click', check1PasswordInterference);
        document.getElementById('clearCredentials').addEventListener('click', clearCredentials);
        
        // Initial info
        log('WebAuthn Credential Diagnostics Tool Ready');
        log(`Domain: ${window.location.hostname}`);
        log(`WebAuthn supported: ${!!window.PublicKeyCredential}`);
        log('Click buttons above to run tests...');
    </script>
</body>
</html>
