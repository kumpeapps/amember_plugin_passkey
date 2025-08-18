// JavaScript for passkey registration and login (WebAuthn)
// This should be included on user profile and login pages

document.addEventListener('DOMContentLoaded', function() {
    // Registration
    var regBtn = document.getElementById('register-passkey-btn');
    if (regBtn) {
        regBtn.addEventListener('click', async function() {
            const resp = await fetch('/amember/login?action=passkey-begin-registration');
            const options = await resp.json();
            options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
            options.user.id = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0));
            const cred = await navigator.credentials.create({ publicKey: options });
            const clientData = {
                id: cred.id,
                rawId: btoa(String.fromCharCode(...new Uint8Array(cred.rawId))),
                type: cred.type,
                response: {
                    attestationObject: btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject))),
                    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)))
                }
            };
            await fetch('/amember/login?action=passkey-finish-registration', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ clientData })
            });
            alert('Passkey registered!');
        });
    }

    // Login
    var loginBtn = document.getElementById('passkey-login-btn');
    if (loginBtn) {
        loginBtn.addEventListener('click', async function() {
            const login = document.querySelector('input[name="amember_login"]')?.value;
            if (!login) return alert('Enter your username first.');
            const resp = await fetch('/amember/login?action=passkey-begin-authentication', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ login })
            });
            const options = await resp.json();
            options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
            options.allowCredentials = options.allowCredentials.map(cred => {
                cred.id = Uint8Array.from(atob(cred.id), c => c.charCodeAt(0));
                return cred;
            });
            const assertion = await navigator.credentials.get({ publicKey: options });
            const clientData = {
                id: assertion.id,
                rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))),
                type: assertion.type,
                response: {
                    authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
                    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
                    signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))),
                    userHandle: assertion.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(assertion.response.userHandle))) : null
                }
            };
            await fetch('/amember/login?action=passkey-finish-authentication', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ login, clientData })
            });
            window.location.reload();
        });
    }
});
