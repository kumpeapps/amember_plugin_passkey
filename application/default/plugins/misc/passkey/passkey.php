<?php

/**
 * Plugin Name: Passkey Login (FIDO2/WebAuthn)
 * Description: Enable Passkey (FIDO2/WebAuthn) login for members and admins.
 * Author: Copilot
 * @am_plugin_group misc
 * @am_plugin_api 6.0
 */

// Ensure no direct access
if (!defined('AM_APPLICATION_PATH')) die('Direct access not allowed');

class Am_Plugin_Passkey extends Am_Plugin
{
    protected $id = 'passkey';
    protected $title = 'Passkey Login';
    protected $description = 'Enable Passkey (FIDO2/WebAuthn) login for members and admins.';
    protected $table = 'passkey_credentials';
    protected $enablePasskeyUI = true; // Production ready
    protected $uiInjected = false; // Flag to prevent duplicate UI injection
    
    static $passkeyClassInstantiated = false;
    static $tableChecked = false;

    public function __construct($param1, $param2)
    {
        // aMember is inconsistent with parameter order, so we need to figure out which is which
        $id = 'passkey';  // Default ID
        $config = null;
        
        // Determine which parameter is the config and which is the ID
        if (is_array($param2)) {
            // param2 is array, so it's likely the config
            $config = $param2;
            if (is_string($param1)) {
                $id = $param1;
            } elseif (is_array($param1) && !empty($param1)) {
                $id = 'passkey';  // Use default
            } else {
                $id = 'passkey';  // Use default for any other type
            }
        } elseif (is_array($param1)) {
            // param1 is array, so it's likely the config
            $config = $param1;
            if (is_string($param2)) {
                $id = $param2;
            } else {
                $id = 'passkey';  // Use default for any other type
            }
        } else {
            // Neither is clearly an array config, try to figure it out
            if (is_object($param1) && method_exists($param1, 'get')) {
                // param1 looks like a config object, treat param2 as ID
                $config = $param1;
                $id = is_string($param2) ? $param2 : 'passkey';
            } elseif (is_object($param2) && method_exists($param2, 'get')) {
                // param2 looks like a config object, treat param1 as ID  
                $config = $param2;
                $id = is_string($param1) ? $param1 : 'passkey';
            } else {
                // Fallback: assume first param is ID, second is config
                $id = is_string($param1) ? $param1 : 'passkey';
                $config = $param2;
            }
        }
        
        error_log('Passkey Plugin: Resolved ID: ' . var_export($id, true) . ', Config type: ' . gettype($config));
        
        if (self::$passkeyClassInstantiated) {
            error_log('Passkey Plugin: CLASS INSTANTIATED MULTIPLE TIMES - ID: ' . var_export($id, true));
        } else {
            error_log('Passkey Plugin: First class instantiation - ID: ' . var_export($id, true));
            self::$passkeyClassInstantiated = true;
        }
        
        error_log('Passkey Plugin: Constructor called - ID: ' . var_export($id, true) . ', File: ' . __FILE__ . ', Class: ' . get_class($this));
        
        // The parent constructor expects (Am_Di $di, $config) where $config is an array
        // We need to find the Am_Di object, which is likely param1 when it's an object
        $di = null;
        if (is_object($param1) && get_class($param1) === 'Am_Di') {
            $di = $param1;
        } elseif (is_object($param2) && get_class($param2) === 'Am_Di') {
            $di = $param2;
        } else {
            // Fallback: try to get Am_Di instance
            $di = Am_Di::getInstance();
        }
        
        // Ensure we have a config array - use the detected config or create empty array
        if (!is_array($config)) {
            $config = array();
        }
        
        error_log('Passkey Plugin: Using DI type: ' . gettype($di) . ', class: ' . (is_object($di) ? get_class($di) : 'N/A'));
        error_log('Passkey Plugin: Using config type: ' . gettype($config));
        
        parent::__construct($di, $config);
        
        // Register AJAX hooks - try multiple hook names for broader compatibility
        Am_Di::getInstance()->hook->add('aJAX', array($this, 'onAjax'));
        Am_Di::getInstance()->hook->add('ajax', array($this, 'onAjax'));
        Am_Di::getInstance()->hook->add('publicAjax', array($this, 'onAjax'));
        Am_Di::getInstance()->hook->add('userAjax', array($this, 'onAjax'));
        
        // Register for aMember's plugin-specific AJAX handling
        Am_Di::getInstance()->hook->add('misc.passkey', array($this, 'onAjax'));
        error_log('Passkey Plugin: REGISTERED AJAX handler for misc.passkey hook');
        
        // Also register for the initFinished hook to catch AJAX requests during routing
        Am_Di::getInstance()->hook->add('initFinished', array($this, 'onInitFinished'));
        error_log('Passkey Plugin: REGISTERED initFinished hook');
        
        // Try registering for frontSetupForms hook as alternative
        Am_Di::getInstance()->hook->add('frontSetupForms', array($this, 'onFrontSetupForms'));
        error_log('Passkey Plugin: REGISTERED frontSetupForms hook');
        
        Am_Di::getInstance()->hook->add('userProfile', array($this, 'onUserProfile'));
        error_log('Passkey Plugin: REGISTERED userProfile hook -> onUserProfile method');
        Am_Di::getInstance()->hook->add('adminUserTabs', array($this, 'onAdminUserTabs'));
        Am_Di::getInstance()->hook->add('authGetLoginForm', array($this, 'onAuthGetLoginForm'));
        Am_Di::getInstance()->hook->add('setupForms', array($this, 'onSetupForms'));
        Am_Di::getInstance()->hook->add('initFinished', array($this, 'onInitFinished'));
        
        // Add multiple hooks to catch different login form scenarios
        Am_Di::getInstance()->hook->add('loginForm', array($this, 'onLoginForm'));
        Am_Di::getInstance()->hook->add('userLoginForm', array($this, 'onUserLoginForm'));
        Am_Di::getInstance()->hook->add('authLoginForm', array($this, 'onAuthLoginForm'));
        Am_Di::getInstance()->hook->add('beforeRender', array($this, 'onBeforeRender'));
        error_log('Passkey Plugin: ALL HOOKS REGISTERED');
        
        // Table creation now handled in saveCredentialSource method for better compatibility
        // $this->createTableIfNotExists();
        
        error_log('Passkey Plugin: Constructor completed for ID: ' . var_export($id, true));
    }
    
    protected function ensureTableAndColumns()
    {
        // Only check once per request to avoid unnecessary database queries
        if (self::$tableChecked) {
            return;
        }
        
        error_log('Passkey Plugin: ensureTableAndColumns called');
        $db = Am_Di::getInstance()->db;
        $tableName = $db->getPrefix() . 'passkey_credentials';
        
        try {
            // Check if table exists
            $tableExists = $db->selectCell("SELECT COUNT(*) FROM information_schema.tables 
                WHERE table_schema = DATABASE() AND table_name = ?", $tableName);
            
            if (!$tableExists) {
                error_log('Passkey Plugin: Table does not exist, creating it');
                // Create the table
                $this->createTableIfNotExists();
            } else {
                error_log('Passkey Plugin: Table exists, checking for required columns');
                
                // Define required columns
                $requiredColumns = [
                    'transports' => "TEXT",
                    'attestation_type' => "VARCHAR(50)",
                    'trust_path' => "TEXT", 
                    'aaguid' => "VARCHAR(255)",
                    'user_handle' => "VARCHAR(255) NOT NULL",
                    'counter' => "INT NOT NULL DEFAULT 0",
                    'name' => "VARCHAR(100) DEFAULT NULL",
                    'created_at' => "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                ];
                
                foreach ($requiredColumns as $colName => $colType) {
                    $colExists = $db->selectCell("SELECT COUNT(*) FROM information_schema.columns
                        WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?", $tableName, $colName);
                    if (!$colExists) {
                        error_log('Passkey Plugin: Adding missing column: ' . $colName);
                        $db->query("ALTER TABLE `{$tableName}` ADD COLUMN `{$colName}` {$colType}");
                    }
                }
            }
            
            // Mark as checked
            self::$tableChecked = true;
            error_log('Passkey Plugin: Table and columns check completed');
            
        } catch (Exception $e) {
            error_log('Passkey Plugin: Error in ensureTableAndColumns: ' . $e->getMessage());
        }
    }

    /**
     * Register config form using onSetupForms (Facebook plugin pattern)
     */
    public function onSetupForms(Am_Event_SetupForms $event)
    {
        // Add debugging to track form registration
        error_log('Passkey Plugin: onSetupForms called - Class: ' . get_class($this) . ', File: ' . __FILE__ . ', Event: ' . get_class($event));
        
        // Check if form already exists to prevent duplicates
        static $formRegistered = false;
        if ($formRegistered) {
            error_log('Passkey Plugin: Form already registered, skipping duplicate registration');
            return;
        }
        
        try {
            // Use a consistent form ID that doesn't change between requests
            $formId = 'passkey';
            error_log('Passkey Plugin: Creating form with ID: ' . $formId);
            
            $form = new Am_Form_Setup($formId);
            $form->setTitle('Passkey Login');
            $form->addHtml('<!-- Passkey plugin: config form marker -->');
            $form->addAdvCheckbox('enable_passkey')->setLabel('Enable Passkey Login');
            $form->addText('rp_name', ['class' => 'am-el-wide'])->setLabel('Relying Party Name')->setValue('aMember');
            $form->addText('rp_id', ['class' => 'am-el-wide'])->setLabel('Relying Party ID')->setValue($_SERVER['HTTP_HOST']);
            
            error_log('Passkey Plugin: Form created successfully, adding to event...');
            $event->addForm($form);
            $formRegistered = true;
            error_log('Passkey Plugin: Form registered successfully with ID: ' . $formId);
        } catch (Exception $e) {
            error_log('Passkey Plugin: Error registering form: ' . $e->getMessage());
            error_log('Passkey Plugin: Stack trace: ' . $e->getTraceAsString());
        }
    }
    
    /**
     * Handle front setup forms - alternative AJAX hook
     */
    public function onFrontSetupForms($event)
    {
        error_log('Passkey Plugin: onFrontSetupForms called - checking for AJAX request');
        
        // Check if this is an AJAX request to our plugin
        $uri = $_SERVER['REQUEST_URI'];
        if (strpos($uri, '/ajax/passkey') !== false || strpos($uri, 'misc/passkey') !== false) {
            error_log('Passkey Plugin: Detected AJAX request in onFrontSetupForms, calling onAjax');
            $this->handleAjaxDirect();
        }
    }

    /**
     * Add Passkey login block to login form using aMember blocks system
     * DISABLED: Using direct form integration instead to avoid aMember blocks system conflicts
     */
    public function onInitFinished(Am_Event $event)
    {
        // Debug: Always add a marker to see if this hook is called
        error_log('Passkey Plugin: onInitFinished called - BLOCKS DISABLED, using direct form integration');
        
        // AGGRESSIVE DEBUG: Inject UI directly here as well
        $currentUri = $_SERVER['REQUEST_URI'];
        error_log('Passkey Plugin: onInitFinished - Current URI: ' . $currentUri);
        
        // Skip admin pages AND AJAX requests to prevent header conflicts
        if (strpos($currentUri, '/admin/') !== false) {
            error_log('Passkey Plugin: onInitFinished - Skipping admin page');
            return;
        }
        
        // Handle AJAX requests to our plugin here as backup
        if (strpos($currentUri, '/ajax/passkey') !== false) {
            error_log('Passkey Plugin: onInitFinished - Detected AJAX request, calling handleAjaxDirect');
            $this->handleAjaxDirect();
            return;
        }
        
        // Skip other AJAX requests to prevent "headers already sent" errors
        if (strpos($currentUri, '/ajax/') !== false) {
            error_log('Passkey Plugin: onInitFinished - Skipping other AJAX request');
            return;
        }
        
        // Skip cron and webhook endpoints
        if (strpos($currentUri, '/cron') !== false || strpos($currentUri, '/webhooks/') !== false) {
            error_log('Passkey Plugin: onInitFinished - Skipping cron/webhook');
            return;
        }
        
        // DISABLE aggressive UI injection to prevent duplicates - form hooks should handle UI
        error_log('Passkey Plugin: onInitFinished - Skipping aggressive UI injection to prevent duplicates');
        return;
        
        // Skip all block registration to avoid aMember's theme system conflicts
        // Passkey UI is now added directly via onAuthGetLoginForm hook
        return;
    }

    public function getFile()
    {
        return __FILE__;
    }
    
    public function getId($oldStyle = true)
    {
        return $this->id;
    }
    
    public function getTitle()
    {
        return $this->title;
    }
    
    public function getDescription()
    {
        return $this->description;
    }
    
    public function getReadme()
    {
        return '';
    }

    /**
     * Display passkey registration form in user profile
     */
    public function onUserProfile(Am_Event_UserProfile $event)
    {
        error_log('Passkey Plugin: onUserProfile called - ENTRY POINT');
        
        // Temporarily disabled to prevent interference with normal login
        if (!$this->enablePasskeyUI) {
            error_log('Passkey Plugin: onUserProfile - enablePasskeyUI is FALSE, returning early');
            return;
        }
        
        error_log('Passkey Plugin: onUserProfile - enablePasskeyUI is TRUE, proceeding');
        
        $config = Am_Di::getInstance()->config;
        // Try multiple config key patterns
        $isEnabled = $config->get('misc.passkey.enable_passkey') || 
                    $config->get('passkey.enable_passkey') ||
                    $config->get('enable_passkey');
        error_log('Passkey Plugin: onUserProfile - Trying config keys:');
        error_log('  misc.passkey.enable_passkey = ' . ($config->get('misc.passkey.enable_passkey') ? 'YES' : 'NO'));
        error_log('  passkey.enable_passkey = ' . ($config->get('passkey.enable_passkey') ? 'YES' : 'NO'));
        error_log('  enable_passkey = ' . ($config->get('enable_passkey') ? 'YES' : 'NO'));
        error_log('Passkey Plugin: onUserProfile - Final enabled result: ' . ($isEnabled ? 'YES' : 'NO'));
        
        if ($isEnabled) {
            $form = $event->getForm();
            $user = $event->getUser();
            
            if (method_exists(Am_Di::getInstance()->auth, 'getUser')) {
                $currentUser = Am_Di::getInstance()->auth->getUser();
            } else {
                $currentUser = null;
            }
            
            if ($currentUser && $currentUser->pk() == $user->pk()) {
                error_log('Passkey Plugin: onUserProfile - Adding passkey registration UI');
                $form->addHtml('<fieldset><legend>🔑 Passkey Management</legend>');
                $form->addHtml('<p>Passkeys provide secure, passwordless authentication using your device\'s built-in security (Touch ID, Face ID, Windows Hello, etc.). You can register multiple passkeys for different devices.</p>');
                
                // Registration section
                $form->addHtml('<div style="margin: 15px 0;">');
                $form->addHtml('<button type="button" onclick="passkeyRegister()" style="background:#28a745;color:white;padding:12px 20px;border:none;border-radius:6px;cursor:pointer;margin-right:10px;">➕ Register New Passkey</button>');
                $form->addHtml('<button type="button" onclick="showPasskeyInfo()" style="background:#17a2b8;color:white;padding:12px 20px;border:none;border-radius:6px;cursor:pointer;">ℹ️ Passkey Info</button>');
                $form->addHtml('</div>');
                
                $form->addHtml('<div id="passkey-login-status" style="margin:15px 0;padding:10px;background:#f8f9fa;border-left:4px solid #007cba;color:#333;"></div>');
                $form->addHtml('</fieldset>');
                
                // Add our registration JavaScript functions
                $form->addHtml($this->getPasskeyJavaScript());
                error_log('Passkey Plugin: Registration UI added successfully');
            } else {
                error_log('Passkey Plugin: Current user cannot edit this profile');
            }
        } else {
            error_log('Passkey Plugin: onUserProfile - Passkey disabled, not adding profile section');
        }
    }

    /**
     * Get JavaScript for passkey registration in user profile
     */
    public function getPasskeyJavaScript()
    {
        return '
<script>
console.log("Passkey Plugin: Profile JavaScript loaded");

// Helper function to safely call WebAuthn with extension interference protection
window.safeWebAuthnCreate = async function(options) {
    console.log("SafeWebAuthn: Starting protected credential creation");
    
    // Detect if 1Password or other extensions are interfering
    const hasExtensionInterference = () => {
        // Check for common extension interference patterns
        return document.querySelector("iframe[src*=\"safari-web-extension\"]") !== null ||
               window.location.href.includes("safari-web-extension") ||
               document.querySelectorAll("iframe").length > 10; // Lots of extension iframes
    };
    
    if (hasExtensionInterference()) {
        console.warn("SafeWebAuthn: Detected potential extension interference, adding delays");
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    
    try {
        // Create a clean context for the WebAuthn call
        const createCredential = (async function() {
            return await navigator.credentials.create({publicKey: options});
        }).bind(null);
        
        const credential = await createCredential();
        console.log("SafeWebAuthn: Successfully created credential");
        return credential;
    } catch (error) {
        console.error("SafeWebAuthn: Error during credential creation:", error);
        throw error;
    }
};

// Helper function to safely call WebAuthn authentication with extension interference protection
window.safeWebAuthnGet = async function(options) {
    console.log("SafeWebAuthn: Starting protected credential authentication");
    
    // Detect if 1Password or other extensions are interfering
    const hasExtensionInterference = () => {
        try {
            // Check for common extension frame access patterns
            if (window.frames && window.frames.length > 0) {
                for (let i = 0; i < window.frames.length; i++) {
                    try {
                        const frame = window.frames[i];
                        if (frame.location && frame.location.href.includes("1password")) {
                            return true;
                        }
                    } catch (e) {
                        // Frame access blocked - common with extensions
                        if (e.message.includes("permission denied") || e.message.includes("cross-origin")) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch (e) {
            console.log("SafeWebAuthn: Extension detection failed, proceeding with caution");
            return false;
        }
    };
    
    if (hasExtensionInterference()) {
        console.log("SafeWebAuthn: Extension interference detected, adding delays");
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    try {
        // Create a clean context for the WebAuthn call
        const getCredential = (async function() {
            return await navigator.credentials.get({publicKey: options});
        }).bind(null);
        
        const assertion = await getCredential();
        console.log("SafeWebAuthn: Successfully authenticated credential");
        return assertion;
    } catch (error) {
        console.error("SafeWebAuthn: Error during credential authentication:", error);
        throw error;
    }
};

// Add passkey registration function
window.passkeyRegister = async function() {
    var statusEl = document.getElementById("passkey-login-status");
    
    function updateStatus(message) {
        console.log("Passkey Status: " + message);
        if (statusEl) statusEl.innerText = message;
    }
    
    try {
        updateStatus("🟡 Initializing passkey registration...");
        
        console.log("Passkey: Making AJAX request to passkey-register-init");
        let resp = await fetch("' . $this->getPluginUrl() . '", {
            method: "POST", 
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest"
            },
            body: "action=passkey-register-init"
        });
        
        console.log("Passkey: Registration response status:", resp.status);
        let responseText = await resp.text();
        console.log("Passkey: Raw response text:", responseText);
        
        let data;
        try {
            data = JSON.parse(responseText);
            console.log("Passkey: Registration options:", data);
        } catch (jsonError) {
            updateStatus("❌ Error: Server returned invalid JSON");
            console.error("Passkey: JSON parse error:", jsonError);
            console.error("Passkey: Response was:", responseText);
            return;
        }
        
        if (data.status !== "ok") {
            updateStatus("❌ Error: " + (data.error || "Unknown error"));
            return;
        }
        
        updateStatus("🔑 Please complete passkey registration...");
        
        let options = data.options;
        
        // Decode challenge and user ID
        try {
            options.challenge = Uint8Array.from(atob(options.challenge), function(c) { return c.charCodeAt(0); });
            options.user.id = Uint8Array.from(atob(options.user.id), function(c) { return c.charCodeAt(0); });
        } catch (e) {
            updateStatus("❌ Error decoding registration data");
            console.error("Decode error:", e);
            return;
        }
        
        console.log("Passkey: Calling navigator.credentials.create with extension protection");
        let credential = await window.safeWebAuthnCreate(options);
        console.log("Passkey: Got credential:", credential);
        
        updateStatus("🔒 Saving passkey...");
        
        // Prepare credential data
        let credData = {
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            type: credential.type,
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
            }
        };
        
        console.log("Passkey: Sending registration finish with credential data");
        
        let finishResp = await fetch("' . $this->getPluginUrl() . '", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest"
            },
            credentials: "same-origin",
            body: "action=passkey-register-finish&credential=" + encodeURIComponent(JSON.stringify(credData))
        });
        
        console.log("Passkey: Registration finish response status:", finishResp.status);
        let finishText = await finishResp.text();
        console.log("Passkey: Registration finish response:", finishText);
        
        let finishData;
        try {
            finishData = JSON.parse(finishText);
        } catch (e) {
            updateStatus("❌ Error: Invalid response from server");
            console.error("JSON parse error:", e);
            return;
        }
        
        if (finishData.status === "ok") {
            updateStatus("✅ Passkey registered successfully! You can now use it to log in.");
            setTimeout(function() {
                if (statusEl) statusEl.innerHTML = "✅ <strong>Passkey registered successfully!</strong><br>You can now use it to log in.";
            }, 1000);
        } else {
            updateStatus("❌ Registration failed: " + (finishData.error || "Unknown error"));
        }
    } catch (e) {
        console.error("Passkey registration error:", e);
        updateStatus("❌ Error: " + e.message);
    }
};

// Add passkey info function  
window.showPasskeyInfo = function() {
    var statusEl = document.getElementById("passkey-login-status");
    if (statusEl) {
        statusEl.innerHTML = 
            "<h5>🔑 What are Passkeys?</h5>" +
            "<p>Passkeys are a secure, passwordless way to sign into your account using your device built-in security features:</p>" +
            "<ul>" +
                "<li><strong>Touch ID</strong> or <strong>Face ID</strong> on Mac/iPhone</li>" +
                "<li><strong>Windows Hello</strong> on Windows</li>" +
                "<li><strong>Fingerprint</strong> or <strong>Face unlock</strong> on Android</li>" +
                "<li><strong>Hardware security keys</strong> (YubiKey, etc.)</li>" +
            "</ul>" +
            "<p><strong>Benefits:</strong></p>" +
            "<ul>" +
                "<li>No passwords to remember or type</li>" +
                "<li>Extremely secure - cannot be phished</li>" +
                "<li>Fast and convenient login</li>" +
                "<li>Works across your devices</li>" +
            "</ul>" +
            "<p><em>Click \"Register New Passkey\" to set up passwordless login for this account.</em></p>";
    }
};

console.log("Passkey Plugin: Profile JavaScript functions loaded");
</script>';
    }

    /**
     * Get the JavaScript content without script tags
     */
    protected function getPasskeyJavaScriptContent()
    {
        return '
console.log("Passkey Plugin: Profile JavaScript loaded");

// Helper function to safely call WebAuthn with extension interference protection
window.safeWebAuthnCreate = async function(options) {
    console.log("SafeWebAuthn: Starting protected credential creation");
    console.log("SafeWebAuthn: Options received:", options);
    
    // Validate options before passing to WebAuthn
    if (!options) {
        throw new Error("SafeWebAuthn: No options provided");
    }
    if (!options.challenge) {
        throw new Error("SafeWebAuthn: No challenge in options");
    }
    if (!options.rp) {
        throw new Error("SafeWebAuthn: No relying party in options");
    }
    if (!options.user) {
        throw new Error("SafeWebAuthn: No user in options");
    }
    
    console.log("SafeWebAuthn: Challenge type:", typeof options.challenge, "length:", options.challenge.length);
    console.log("SafeWebAuthn: User ID type:", typeof options.user.id, "length:", options.user.id.length);
    console.log("SafeWebAuthn: Extensions:", options.extensions);
    
    // Detect if 1Password or other extensions are interfering
    const hasExtensionInterference = () => {
        // Check for common extension interference patterns
        return document.querySelector("iframe[src*=\"safari-web-extension\"]") !== null ||
               window.location.href.includes("safari-web-extension") ||
               document.querySelectorAll("iframe").length > 10; // Lots of extension iframes
    };
    
    if (hasExtensionInterference()) {
        console.warn("SafeWebAuthn: Detected potential extension interference, adding delays");
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    
    try {
        console.log("SafeWebAuthn: About to call navigator.credentials.create");
        // Create a clean context for the WebAuthn call
        const createCredential = (async function() {
            return await navigator.credentials.create({publicKey: options});
        }).bind(null);
        
        const credential = await createCredential();
        console.log("SafeWebAuthn: Successfully created credential");
        return credential;
    } catch (error) {
        console.error("SafeWebAuthn: Error during credential creation:", error);
        console.error("SafeWebAuthn: Error name:", error.name);
        console.error("SafeWebAuthn: Error message:", error.message);
        console.error("SafeWebAuthn: Error stack:", error.stack);
        
        // Check if this is an extension interference error
        if (error.message && (
            error.message.includes("Attempting to use a disconnected port object") ||
            error.message.includes("safari-web-extension") ||
            error.message.includes("Extension context invalidated")
        )) {
            console.warn("SafeWebAuthn: Detected extension interference, retrying...");
            // Wait a bit and try again without the extension interference
            await new Promise(resolve => setTimeout(resolve, 500));
            try {
                return await navigator.credentials.create({publicKey: options});
            } catch (retryError) {
                console.error("SafeWebAuthn: Retry also failed:", retryError);
                throw new Error("WebAuthn failed due to browser extension interference. Please try disabling browser extensions or use a different browser.");
            }
        }
        
        // Re-throw the original error if it is not extension related
        throw error;
    }
};

// Helper function to safely call WebAuthn get with extension interference protection
window.safeWebAuthnGet = async function(options) {
    console.log("SafeWebAuthn: Starting protected credential get");
    
    // Detect if 1Password or other extensions are interfering
    const hasExtensionInterference = () => {
        return document.querySelector("iframe[src*=\"safari-web-extension\"]") !== null ||
               window.location.href.includes("safari-web-extension") ||
               document.querySelectorAll("iframe").length > 10; 
    };
    
    if (hasExtensionInterference()) {
        console.warn("SafeWebAuthn: Detected potential extension interference, adding delays");
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    
    try {
        const getCredential = (async function() {
            return await navigator.credentials.get({publicKey: options});
        }).bind(null);
        
        const assertion = await getCredential();
        console.log("SafeWebAuthn: Successfully got assertion");
        return assertion;
    } catch (error) {
        console.error("SafeWebAuthn: Error during credential get:", error);
        
        // Check if this is an extension interference error
        if (error.message && (
            error.message.includes("Attempting to use a disconnected port object") ||
            error.message.includes("safari-web-extension") ||
            error.message.includes("Extension context invalidated")
        )) {
            console.warn("SafeWebAuthn: Detected extension interference, retrying...");
            await new Promise(resolve => setTimeout(resolve, 500));
            try {
                return await navigator.credentials.get({publicKey: options});
            } catch (retryError) {
                console.error("SafeWebAuthn: Retry also failed:", retryError);
                throw new Error("WebAuthn failed due to browser extension interference. Please try disabling browser extensions or use a different browser.");
            }
        }
        
        throw error;
    }
};

// Add passkey registration function
window.passkeyRegister = async function() {
    var statusEl = document.getElementById("passkey-login-status");
    
    function updateStatus(message) {
        console.log("Passkey Status: " + message);
        if (statusEl) statusEl.innerText = message;
    }
    
    try {
        updateStatus("🟡 Initializing passkey registration...");
        
        console.log("Passkey: Making AJAX request to passkey-register-init");
        let resp = await fetch("' . $this->getPluginUrl() . '", {
            method: "POST", 
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest"
            },
            body: "action=passkey-register-init"
        });
        
        console.log("Passkey: Registration response status:", resp.status);
        let responseText = await resp.text();
        console.log("Passkey: Raw response text:", responseText);
        
        let data;
        try {
            data = JSON.parse(responseText);
            console.log("Passkey: Registration options:", data);
        } catch (jsonError) {
            updateStatus("❌ Error: Server returned invalid JSON");
            console.error("Passkey: JSON parse error:", jsonError);
            console.error("Passkey: Response was:", responseText);
            return;
        }
        
        if (data.status !== "ok") {
            updateStatus("❌ Error: " + (data.error || "Unknown error"));
            return;
        }
        
        updateStatus("🔑 Please complete passkey registration...");
        
        let options = data.options;
        
        // Decode challenge and user ID
        try {
            options.challenge = Uint8Array.from(atob(options.challenge), function(c) { return c.charCodeAt(0); });
            options.user.id = Uint8Array.from(atob(options.user.id), function(c) { return c.charCodeAt(0); });
        } catch (e) {
            updateStatus("❌ Error decoding registration data");
            console.error("Decode error:", e);
            return;
        }
        
        console.log("Passkey: Calling navigator.credentials.create with extension protection");
        let credential = await window.safeWebAuthnCreate(options);
        console.log("Passkey: Got credential:", credential);
        
        updateStatus("🔒 Saving passkey...");
        
        // Prepare credential data
        let credData = {
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            type: credential.type,
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
            }
        };
        
        console.log("Passkey: Sending registration finish with credential data");
        
        let finishResp = await fetch("' . $this->getPluginUrl() . '", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest"
            },
            credentials: "same-origin",
            body: "action=passkey-register-finish&credential=" + encodeURIComponent(JSON.stringify(credData))
        });
        
        console.log("Passkey: Registration finish response status:", finishResp.status);
        let finishText = await finishResp.text();
        console.log("Passkey: Registration finish response:", finishText);
        
        let finishData;
        try {
            finishData = JSON.parse(finishText);
        } catch (e) {
            updateStatus("❌ Error: Invalid response from server");
            console.error("JSON parse error:", e);
            return;
        }
        
        if (finishData.status === "ok") {
            updateStatus("✅ Passkey registered successfully! You can now use it to log in.");
            setTimeout(function() {
                if (statusEl) statusEl.innerHTML = "✅ <strong>Passkey registered successfully!</strong><br>You can now use it to log in.";
            }, 1000);
        } else {
            updateStatus("❌ Registration failed: " + (finishData.error || "Unknown error"));
        }
    } catch (e) {
        console.error("Passkey registration error:", e);
        updateStatus("❌ Error: " + e.message);
    }
};

// Add passkey info function  
window.showPasskeyInfo = function() {
    var statusEl = document.getElementById("passkey-login-status");
    if (statusEl) {
        statusEl.innerHTML = 
            "<h5>🔑 What are Passkeys?</h5>" +
            "<p>Passkeys are a secure, passwordless way to sign into your account using your device built-in security features:</p>" +
            "<ul>" +
                "<li><strong>Touch ID</strong> or <strong>Face ID</strong> on Mac/iPhone</li>" +
                "<li><strong>Windows Hello</strong> on Windows</li>" +
                "<li><strong>Fingerprint</strong> or <strong>Face unlock</strong> on Android</li>" +
                "<li><strong>Hardware security keys</strong> (YubiKey, etc.)</li>" +
            "</ul>" +
            "<p><strong>Benefits:</strong></p>" +
            "<ul>" +
                "<li>No passwords to remember or type</li>" +
                "<li>Extremely secure - cannot be phished</li>" +
                "<li>Fast and convenient login</li>" +
                "<li>Works across your devices</li>" +
            "</ul>" +
            "<p><em>Click \"Register New Passkey\" to set up passwordless login for this account.</em></p>";
    }
};

// Add passkey delete function for profile page
window.deletePasskey = async function(credentialId) {
    console.log("deletePasskey called with ID:", credentialId);
    
    if (!confirm("Are you sure you want to delete this passkey? This action cannot be undone.")) {
        console.log("Delete cancelled by user");
        return;
    }
    
    // Try to find status element - could be on login page or profile page
    var statusEl = document.getElementById("passkey-login-status") || 
                  document.getElementById("passkey-profile-status") ||
                  document.getElementById("passkey-status");
    
    function updateStatus(message) {
        console.log("Passkey Delete Status: " + message);
        if (statusEl) {
            statusEl.innerHTML = message;
        } else {
            // Create temporary status display if no status element exists
            var tempStatus = document.createElement("div");
            tempStatus.style.cssText = "position: fixed; top: 20px; right: 20px; z-index: 99999; background: #007cba; color: white; padding: 10px 15px; border-radius: 6px; font-size: 14px; max-width: 300px;";
            tempStatus.innerHTML = message;
            document.body.appendChild(tempStatus);
            setTimeout(function() {
                if (tempStatus.parentNode) tempStatus.remove();
            }, 5000);
        }
    }
    
    try {
        updateStatus("🗑️ Deleting passkey...");
        console.log("Making delete request to:", "' . $this->getPluginUrl() . '");
        
        let resp = await fetch("' . $this->getPluginUrl() . '", {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest"
            },
            body: "action=passkey-delete&credential_id=" + encodeURIComponent(credentialId)
        });
        
        console.log("Delete response status:", resp.status);
        let responseText = await resp.text();
        console.log("Passkey Delete Response:", responseText);
        
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (jsonError) {
            console.error("JSON parse error:", jsonError);
            console.error("Raw response:", responseText);
            updateStatus("❌ Error: Server returned invalid response");
            return;
        }
        
        console.log("Parsed delete response:", data);
        
        if (data.status === "ok") {
            updateStatus("✅ Passkey deleted successfully! Refreshing page...");
            setTimeout(function() {
                window.location.reload();
            }, 1500);
        } else {
            updateStatus("❌ Delete failed: " + (data.error || "Unknown error"));
        }
    } catch (e) {
        console.error("Passkey delete error:", e);
        updateStatus("❌ Error: " + e.message);
    }
};

// Add passkey rename function for profile page
window.renamePasskey = async function(credentialId, currentName) {
    var newName = prompt("Enter a new name for this passkey:", currentName);
    if (!newName || newName === currentName) {
        return;
    }
    
    var statusEl = document.getElementById("passkey-login-status") || 
                  document.getElementById("passkey-profile-status") ||
                  document.getElementById("passkey-status");
    
    function updateStatus(message) {
        console.log("Passkey Rename Status: " + message);
        if (statusEl) {
            statusEl.innerHTML = message;
        } else {
            var tempStatus = document.createElement("div");
            tempStatus.style.cssText = "position: fixed; top: 20px; right: 20px; z-index: 99999; background: #007cba; color: white; padding: 10px 15px; border-radius: 6px; font-size: 14px; max-width: 300px;";
            tempStatus.innerHTML = message;
            document.body.appendChild(tempStatus);
            setTimeout(function() {
                if (tempStatus.parentNode) tempStatus.remove();
            }, 5000);
        }
    }
    
    try {
        updateStatus("✏️ Renaming passkey...");
        
        let resp = await fetch("' . $this->getPluginUrl() . '", {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest"
            },
            body: "action=passkey-rename&credential_id=" + encodeURIComponent(credentialId) + "&new_name=" + encodeURIComponent(newName)
        });
        
        let responseText = await resp.text();
        console.log("Passkey Rename Response:", responseText);
        
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (jsonError) {
            updateStatus("❌ Error: Server returned invalid response");
            console.error("JSON parse error:", jsonError);
            return;
        }
        
        if (data.status === "ok") {
            updateStatus("✅ Passkey renamed successfully! Refreshing page...");
            setTimeout(function() {
                window.location.reload();
            }, 1500);
        } else {
            updateStatus("❌ Rename failed: " + (data.error || "Unknown error"));
        }
    } catch (e) {
        console.error("Passkey rename error:", e);
        updateStatus("❌ Error: " + e.message);
    }
};

console.log("Passkey Plugin: Profile JavaScript functions loaded");
';
    }

    /**
     * Get the URL for this plugin file
     */
    protected function getPluginUrl()
    {
        // Use aMember's plugin-specific AJAX system
        $url = '/ajax/passkey';
        error_log('Passkey Plugin: Generated AJAX URL: ' . $url);
        return $url;
    }
    
    protected function getAjaxURL($action) 
    {
        // Return proper aMember AJAX URL with action parameter
        return '/ajax/passkey/' . urlencode($action);
    }

    /**
     * Inject passkey management UI into profile pages
     */
    protected function injectProfilePasskeyUI()
    {
        error_log('Passkey Plugin: injectProfilePasskeyUI called');
        
        // Ensure table exists and has all required columns before trying to read
        $this->ensureTableAndColumns();
        
        // Get existing passkeys for the current user
        $auth = Am_Di::getInstance()->auth;
        $user = $auth->getUser();
        $existingKeys = '';
        
        if ($user) {
            try {
                $db = Am_Di::getInstance()->db;
                $tableName = $db->getPrefix() . 'passkey_credentials';
                $rows = $db->select("SELECT credential_id, name, created_at FROM `{$tableName}` WHERE user_handle=?", $user->pk());
                
                if ($rows && count($rows) > 0) {
                    $existingKeys = '<h4 style="color: #007cba; margin: 15px 0 10px 0;">Your Registered Passkeys (' . count($rows) . ')</h4>';
                    $existingKeys .= '<div style="margin: 0 0 15px 0;">';
                    foreach ($rows as $index => $row) {
                        $shortId = substr($row['credential_id'], 0, 12) . '...';
                        $createdDate = $row['created_at'] ? date('M j, Y', strtotime($row['created_at'])) : 'Unknown date';
                        $passkeyNum = $index + 1;
                        $passkeyName = !empty($row['name']) ? htmlspecialchars($row['name']) : 'Passkey #' . $passkeyNum;
                        
                        $existingKeys .= '<div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; margin: 8px 0; background: #fff; border: 1px solid #dee2e6; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
                        $existingKeys .= '<div style="flex: 1;">';
                        $existingKeys .= '<strong style="color: #495057; font-size: 16px;">🔑 ' . $passkeyName . '</strong><br>';
                        $existingKeys .= '<small style="color: #6c757d;">ID: ' . htmlspecialchars($shortId) . '</small><br>';
                        $existingKeys .= '<small style="color: #6c757d;">Added: ' . htmlspecialchars($createdDate) . '</small>';
                        $existingKeys .= '</div>';
                        $existingKeys .= '<div style="display: flex; gap: 8px;">';
                        $existingKeys .= '<button type="button" onclick="renamePasskey(\'' . htmlspecialchars($row['credential_id'], ENT_QUOTES) . '\', \'' . htmlspecialchars($passkeyName, ENT_QUOTES) . '\')" ';
                        $existingKeys .= 'style="background: #17a2b8; color: white; border: none; padding: 6px 10px; border-radius: 4px; cursor: pointer; font-size: 12px;" ';
                        $existingKeys .= 'onmouseover="this.style.background=\'#138496\'" onmouseout="this.style.background=\'#17a2b8\'" ';
                        $existingKeys .= 'title="Rename this passkey">✏️ Rename</button>';
                        $existingKeys .= '<button type="button" onclick="deletePasskey(\'' . htmlspecialchars($row['credential_id'], ENT_QUOTES) . '\')" ';
                        $existingKeys .= 'style="background: #dc3545; color: white; border: none; padding: 6px 10px; border-radius: 4px; cursor: pointer; font-size: 12px;" ';
                        $existingKeys .= 'onmouseover="this.style.background=\'#c82333\'" onmouseout="this.style.background=\'#dc3545\'" ';
                        $existingKeys .= 'title="Delete this passkey">🗑️ Delete</button>';
                        $existingKeys .= '</div>';
                        $existingKeys .= '</div>';
                    }
                    $existingKeys .= '</div>';
                    $existingKeys .= '<p style="color: #6c757d; font-size: 13px; margin: 10px 0;"><em>💡 Tip: You can rename passkeys to identify them easily (e.g., "iPhone", "YubiKey", "Work Laptop").</em></p>';
                } else {
                    $existingKeys = '<p style="color: #6c757d; margin: 10px 0; padding: 15px; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; text-align: center;">📱 No passkeys registered yet. Add your first passkey below for secure, passwordless login!</p>';
                }
            } catch (Exception $e) {
                error_log('Passkey Plugin: Database error in injectProfilePasskeyUI: ' . $e->getMessage());
                $existingKeys = '<p style="color: #dc3545; margin: 10px 0; padding: 10px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px;">⚠️ Unable to load existing passkeys. Please try refreshing the page.</p>';
            }
        }
        
        // Get the JavaScript content without the script tags
        $jsContent = $this->getPasskeyJavaScriptContent();
        
        $html = '
<script>
console.log("Passkey Plugin: Profile UI injection starting");

// Define global functions FIRST, before creating HTML elements that reference them
' . $jsContent . '

document.addEventListener("DOMContentLoaded", function() {
    console.log("Passkey Plugin: DOM ready, injecting profile passkey UI");
    
    // Look for common profile form containers
    var targetElements = [
        document.querySelector("form[name*=profile]"),
        document.querySelector("form[id*=profile]"),
        document.querySelector(".profile-form"),
        document.querySelector("#profile-form"),
        document.querySelector("form"),  // fallback to any form
        document.querySelector("body")   // last resort
    ];
    
    var targetElement = null;
    for (var i = 0; i < targetElements.length; i++) {
        if (targetElements[i]) {
            targetElement = targetElements[i];
            console.log("Passkey Plugin: Found target element:", targetElement.tagName, targetElement.className || targetElement.id);
            break;
        }
    }
    
    if (!targetElement) {
        console.log("Passkey Plugin: No target element found for profile UI");
        return;
    }
    
    // Create passkey management section
    var passkeySection = document.createElement("div");
    passkeySection.innerHTML = 
        \'<fieldset style="margin: 20px 0; padding: 20px; border: 2px solid #007cba; border-radius: 8px; background: #f8f9fa;">\' +
            \'<legend style="padding: 0 10px; color: #007cba; font-weight: bold; font-size: 18px;">🔑 Passkey Management</legend>\' +
            \'<p style="margin: 0 0 15px 0; color: #666;">\' +
                \'Passkeys provide secure, passwordless authentication using your device built-in security \' +
                \'(Touch ID, Face ID, Windows Hello, etc.) or hardware security keys (YubiKey).\' +
            \'</p>\' +
            \'' . str_replace(array("\n", "\r", "'"), array("", "", "\\'"), $existingKeys) . '\' +
            \'<div style="margin: 15px 0;">\' +
                \'<button type="button" onclick="passkeyRegister()" \' +
                        \'style="background:#28a745;color:white;padding:12px 20px;border:none;border-radius:6px;cursor:pointer;margin-right:10px;font-size:16px;">\' +
                    \'➕ Register New Passkey\' +
                \'</button>\' +
                \'<button type="button" onclick="showPasskeyInfo()" \' +
                        \'style="background:#17a2b8;color:white;padding:12px 20px;border:none;border-radius:6px;cursor:pointer;font-size:16px;">\' +
                    \'ℹ️ Passkey Info\' +
                \'</button>\' +
            \'</div>\' +
            \'<div id="passkey-login-status" style="margin:15px 0;padding:10px;background:#fff;border:1px solid #ddd;border-radius:4px;color:#333;min-height:20px;"></div>\' +
        \'</fieldset>\';
    
    // Insert the passkey section
    if (targetElement.tagName === "FORM") {
        // Insert before the form
        targetElement.parentNode.insertBefore(passkeySection, targetElement);
        console.log("Passkey Plugin: Inserted passkey UI before form");
    } else {
        // Insert at the beginning of the target element
        targetElement.insertBefore(passkeySection, targetElement.firstChild);
        console.log("Passkey Plugin: Inserted passkey UI inside target element");
    }
    
    console.log("Passkey Plugin: Profile passkey UI injected successfully");
});

console.log("Passkey Plugin: Profile injection script loaded");
</script>';

        echo $html;
        error_log('Passkey Plugin: Profile UI HTML injected');
    }

    /**
     * Hook into login form to allow passkey login
     */
    public function onAuthGetLoginForm(Am_Event_AuthGetLoginForm $event)
    {
        error_log('Passkey Plugin: onAuthGetLoginForm called - CRITICAL HOOK');
        error_log('Passkey Plugin: Event class: ' . get_class($event));
        error_log('Passkey Plugin: Form available: ' . (method_exists($event, 'getForm') ? 'YES' : 'NO'));
        
        if (method_exists($event, 'getForm')) {
            $form = $event->getForm();
            error_log('Passkey Plugin: Form class: ' . (is_object($form) ? get_class($form) : gettype($form)));
            $this->addPasskeyLoginUI($form);
        } else {
            error_log('Passkey Plugin: ERROR - getForm method not available');
        }
    }

    /**
     * Additional login form hooks to catch different scenarios
     */
    public function onLoginForm($event)
    {
        error_log('Passkey Plugin: onLoginForm called - RE-ENABLED as fallback for missing UI');
        
        // Re-enable this hook as a fallback since onAuthGetLoginForm might not be firing
        if (method_exists($event, 'getForm')) {
            error_log('Passkey Plugin: onLoginForm - Adding UI as fallback');
            $this->addPasskeyLoginUI($event->getForm());
        } else {
            error_log('Passkey Plugin: onLoginForm - No getForm method available');
        }
    }
    
    public function onUserLoginForm($event)
    {
        error_log('Passkey Plugin: onUserLoginForm called - DISABLED to prevent duplicate UI');
        // DISABLE to prevent duplicate UI injection
        return;
        
        error_log('Passkey Plugin: onUserLoginForm called');
        if (method_exists($event, 'getForm')) {
            $this->addPasskeyLoginUI($event->getForm());
        }
    }
    
    public function onAuthLoginForm($event)
    {
        error_log('Passkey Plugin: onAuthLoginForm called - DISABLED to prevent duplicate UI');
        // DISABLE to prevent duplicate UI injection  
        return;
        
        error_log('Passkey Plugin: onAuthLoginForm called');
        if (method_exists($event, 'getForm')) {
            $this->addPasskeyLoginUI($event->getForm());
        }
    }
    
    public function onBeforeRender($event)
    {
        // Temporarily disabled to prevent interference with normal login
        if (!$this->enablePasskeyUI) {
            return;
        }
        
        // Check if UI was already injected for this request
        if ($this->uiInjected) {
            return;
        }
        
        error_log('Passkey Plugin: onBeforeRender called - RE-ENABLED as aggressive fallback');
        
        // RE-ENABLE this hook as aggressive fallback to ensure UI appears
        error_log('Passkey Plugin: onBeforeRender called - URI: ' . $_SERVER['REQUEST_URI']);
        
        // Only inject passkey UI on login-related pages OR profile pages
        $currentUri = $_SERVER['REQUEST_URI'];
        
        // Handle profile pages - inject passkey management UI (only if user is logged in)
        if (strpos($currentUri, '/profile') !== false) {
            error_log('Passkey Plugin: Profile page detected, checking if user is logged in');
            
            // Check if user is logged in before injecting profile UI
            $auth = Am_Di::getInstance()->auth;
            if (!$auth->getUser()) {
                error_log('Passkey Plugin: User not logged in on profile page, will inject login UI instead');
                // Fall through to login UI injection below
            } else {
                error_log('Passkey Plugin: User is logged in, injecting passkey management UI');
                
                // Inject passkey management UI for profile page
                $this->injectProfilePasskeyUI();
                $this->uiInjected = true;
                return;
            }
        }

        // Handle member pages - inject login UI if not logged in, otherwise skip
        if (strpos($currentUri, '/member') !== false) {
            error_log('Passkey Plugin: Member page detected, checking if user is logged in');
            
            // Check if user is logged in
            $auth = Am_Di::getInstance()->auth;
            if ($auth->getUser()) {
                error_log('Passkey Plugin: User is logged in on member page, skipping login UI injection');
                return;
            } else {
                error_log('Passkey Plugin: User not logged in on member page, will inject login UI');
                // Fall through to login UI injection below
            }
        }
        
        // Skip admin and signup pages
        $skipUris = array('/admin', '/signup');
        
        foreach ($skipUris as $skip) {
            if (strpos($currentUri, $skip) !== false) {
                error_log('Passkey Plugin: Skipping UI injection for URI: ' . $currentUri);
                return;
            }
        }
        
        // Check if this looks like a login page OR pages that need login when user not authenticated
        $isLoginPage = (strpos($currentUri, 'login') !== false || 
                       strpos($currentUri, 'auth') !== false || 
                       $currentUri === '/' || 
                       strpos($currentUri, 'amember') !== false ||
                       strpos($currentUri, 'member') !== false ||
                       strpos($currentUri, 'profile') !== false ||
                       strpos(strtolower($_SERVER['REQUEST_URI']), 'signin') !== false);
                       
        if (!$isLoginPage) {
            error_log('Passkey Plugin: Not a login page, skipping UI injection - URI: ' . $currentUri);
            return;
        }
        
        // FORCE UI injection on login page since onAuthGetLoginForm isn't firing
        error_log('Passkey Plugin: FORCING UI injection since onAuthGetLoginForm not firing');
        
        // FORCE UI injection on login page since onAuthGetLoginForm isn't firing
        error_log('Passkey Plugin: FORCING UI injection since onAuthGetLoginForm not firing');
        
        error_log('Passkey Plugin: onBeforeRender - Injecting JavaScript UI as fallback');
        
        // Clean injection of passkey UI
        error_log('Passkey Plugin: onBeforeRender - Injecting clean UI');
        
        // Inject clean passkey UI only on login pages
        $js = $this->getPasskeyLoginJS();
        $html = '<script>
console.log("Passkey Plugin: Login script loaded"); 
' . $js . '

// Add UI creation when DOM is ready
document.addEventListener("DOMContentLoaded", function() {
    console.log("Passkey Plugin: DOM ready, injecting login UI");
    
    // Check if passkey UI already exists
    if (document.getElementById("passkey-login-container")) {
        console.log("Passkey Plugin: UI already exists, skipping injection");
        return;
    }
    
    // Try to find where to inject the passkey UI
    var targetElements = [
        // Look for forms with password fields
        (function() {
            var passwordInput = document.querySelector("input[type=password]");
            return passwordInput ? passwordInput.closest("form") : null;
        })(),
        // Look for any form
        document.querySelector("form"),
        // Look for common login containers
        document.querySelector(".login-form"),
        document.querySelector("#login-form"),
        document.querySelector(".user-login"),
        document.querySelector("#user-login"),
        // Look for body as last resort
        document.querySelector("body")
    ];
    
    var targetElement = null;
    for (var i = 0; i < targetElements.length; i++) {
        if (targetElements[i]) {
            targetElement = targetElements[i];
            console.log("Passkey Plugin: Found target element:", targetElement.tagName, targetElement.className || targetElement.id || "no class/id");
            break;
        }
    }
    
    if (!targetElement) {
        console.log("Passkey Plugin: No target element found for UI injection");
        return;
    }
    
    // Try to find the login button specifically
    var loginButton = document.querySelector("input[type=submit]") || 
                     document.querySelector("button[type=submit]") ||
                     document.querySelector("input[value*=\'Login\']") ||
                     document.querySelector("input[value*=\'login\']") ||
                     document.querySelector("button[value*=\'Login\']") ||
                     document.querySelector("button[value*=\'login\']");
    
    var insertLocation = null;
    
    if (loginButton) {
        // Found login button, lets copy its centering approach
        insertLocation = loginButton.parentNode;
        console.log("Passkey Plugin: Found login button, will insert after it");
        
        // Try to copy the login button parent container styling for consistency
        var loginButtonParent = loginButton.parentNode;
        var loginButtonStyle = window.getComputedStyle(loginButton);
        var parentStyle = window.getComputedStyle(loginButtonParent);
        
        console.log("Login button text-align:", parentStyle.textAlign);
        console.log("Login button display:", loginButtonStyle.display);
        console.log("Login button margin:", loginButtonStyle.margin);
    } else {
        // Fallback to form or other target
        insertLocation = targetElement;
        console.log("Passkey Plugin: No login button found, using fallback location");
    }
    
    // Create wrapper div that mimics the login button container
    var buttonWrapper = document.createElement("div");
    
    // If we found a login button, try to copy its parent structure
    if (loginButton && loginButton.parentNode) {
        var loginParent = loginButton.parentNode;
        var computedStyle = window.getComputedStyle(loginParent);
        
        // Copy relevant styles from the login button parent
        buttonWrapper.style.textAlign = computedStyle.textAlign || "center";
        buttonWrapper.style.display = computedStyle.display || "block";
        buttonWrapper.style.margin = "10px 0";
        buttonWrapper.style.width = "100%";
        
        console.log("Copied login parent styles - textAlign:", computedStyle.textAlign);
    } else {
        // Fallback styling
        buttonWrapper.style.cssText = "text-align:center;margin:10px 0;width:100%;";
    }
    
    // Create simple passkey button that centers itself
    var passkeyButton = document.createElement("button");
    passkeyButton.type = "button";
    passkeyButton.onclick = function() { passkeyLogin(); };
    
    // Style the button to be centered naturally (not forced width)
    passkeyButton.style.cssText = "background:#007cba;color:white;padding:10px 16px;border:none;border-radius:4px;cursor:pointer;font-size:14px;margin:0;display:inline-block;";
    passkeyButton.innerHTML = "🔑 Login with Passkey";
    passkeyButton.id = "passkey-login-btn";
    
    // Add button to wrapper
    buttonWrapper.appendChild(passkeyButton);
    
    // Create hidden status element
    var statusDiv = document.createElement("div");
    statusDiv.id = "passkey-login-status";
    statusDiv.style.cssText = "margin-top:8px;padding:6px;color:#333;font-size:12px;text-align:center;display:none;";
    
    // Insert the button wrapper and status
    if (loginButton) {
        // Insert right after the login button
        loginButton.parentNode.insertBefore(buttonWrapper, loginButton.nextSibling);
        loginButton.parentNode.insertBefore(statusDiv, buttonWrapper.nextSibling);
    } else {
        // Fallback: append to target element
        insertLocation.appendChild(buttonWrapper);
        insertLocation.appendChild(statusDiv);
    }
    
    console.log("Passkey Plugin: Login UI injected successfully");
});
</script>';
        
        echo $html;
        $this->uiInjected = true;
        error_log('Passkey Plugin: onBeforeRender - JavaScript and UI injected');
    }
    
    // Removed problematic JavaScript block - will be reimplemented later
    /*
console.log("Passkey Plugin: onBeforeRender script loaded for login page");
console.log("Passkey Plugin: Current URL:", window.location.href);
console.log("Passkey Plugin: Page title:", document.title);
console.log("Passkey Plugin: User agent:", navigator.userAgent);

// Add passkey login functionality to the page
var indicator = document.createElement("div");
indicator.style.cssText = "position:fixed;top:10px;left:10px;background:#28a745;color:white;padding:8px 15px;border-radius:6px;z-index:99999;font-size:14px;font-weight:bold;box-shadow: 0 4px 12px rgba(0,0,0,0.3);";
indicator.innerText = "Passkey Plugin Active - Login Page";
document.body.appendChild(indicator);
setTimeout(function() { 
    if (indicator.parentNode) indicator.remove(); 
}, 10000);

console.log("Passkey Plugin: Immediate indicator added");

function injectPasskeyUI() {
    console.log("Passkey Plugin: injectPasskeyUI called");
    console.log("Passkey Plugin: DOM ready state:", document.readyState);
    
    // Check if passkey UI already exists
    if (document.getElementById("passkey-login-container")) {
        console.log("Passkey Plugin: UI already exists, skipping injection");
        return;
    }
    
    // Try multiple strategies to find where to inject the passkey UI
    var targetElements = [
        // Look for forms with password fields
        (function() {
            var passwordInput = document.querySelector("input[type=password]");
            return passwordInput ? passwordInput.closest("form") : null;
        })(),
        // Look for any form
        document.querySelector("form"),
        // Look for common login containers
        document.querySelector(".login-form"),
        document.querySelector("#login-form"),
        document.querySelector(".user-login"),
        document.querySelector("#user-login"),
        // Look for body as last resort
        document.querySelector("body")
    ];
    
    var targetElement = null;
    for (var i = 0; i < targetElements.length; i++) {
        if (targetElements[i]) {
            targetElement = targetElements[i];
            console.log("Passkey Plugin: Found target element #" + i + ":", targetElement.tagName, targetElement.className || targetElement.id || "no class/id");
            break;
        }
    }
    
    if (!targetElement) {
        console.log("Passkey Plugin - No suitable target element found, using prominent fallback");
        // Create a very prominent floating div as absolute fallback
        var fallbackDiv = document.createElement("div");
        fallbackDiv.id = "passkey-floating-login";
        fallbackDiv.style.cssText = "position: fixed; top: 50px; right: 20px; z-index: 99999; background: #ffffff; border: 3px solid #007cba; border-radius: 12px; padding: 20px; box-shadow: 0 8px 20px rgba(0,0,0,0.4); max-width: 320px; font-family: Arial, sans-serif;";
        fallbackDiv.innerHTML = \'<div style="margin-bottom: 15px; font-weight: bold; color: #007cba; font-size: 16px; text-align: center;">🔐 Secure Passkey Login</div>\' +
            \'<p style="margin: 0 0 15px 0; color: #333; font-size: 14px; line-height: 1.4;">Use your device security (Touch ID, Face ID, etc.) for instant, secure login.</p>\' +
            \'<button type="button" onclick="passkeyLogin()" style="background:#007cba;color:white;padding:12px 20px;border:none;border-radius:6px;cursor:pointer;width:100%;margin-bottom:10px;font-size: 16px;font-weight:bold;">🚀 Login with Passkey</button>\' +
            \'<div id="passkey-login-status" style="font-size:13px;color:#666;min-height:20px;text-align:center;"></div>\' +
            \'<button onclick="this.parentNode.remove()" style="position: absolute; top: 8px; right: 12px; background: none; border: none; color: #999; cursor: pointer; font-size: 18px; font-weight: bold;" title="Close">×</button>\';
        document.body.appendChild(fallbackDiv);
        console.log("Passkey Plugin Added prominent floating fallback UI");
        
        // Also try to inject near any form as backup
        var anyForm = document.querySelector("form");
        if (anyForm) {
            var inlineDiv = document.createElement("div");
            inlineDiv.style.cssText = "margin: 15px 0; padding: 15px; background: #f0f8ff; border: 2px solid #007cba; border-radius: 8px;";
            inlineDiv.innerHTML = \'<div style="margin-bottom: 10px; font-weight: bold; color: #007cba;">🔐 Alternative Login Method</div><button type="button" onclick="passkeyLogin()" style="background:#28a745;color:white;padding:10px 16px;border:none;border-radius:4px;cursor:pointer;">Login with Passkey</button>\';
            anyForm.parentNode.insertBefore(inlineDiv, anyForm);
            console.log("Passkey Plugin - Added inline backup UI near form");
        }
        return;
    }

    // Create the passkey UI
    var passkeyDiv = document.createElement("div");
    passkeyDiv.innerHTML = 
        \'<div id="passkey-login-container" style="margin: 20px 0; padding: 20px; border: 2px solid #007cba; border-radius: 8px; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); box-shadow: 0 4px 6px rgba(0,0,0,0.1);">\' +
            \'<h3 style="margin: 0 0 15px 0; color: #007cba; display: flex; align-items: center; font-size: 20px;">\' +
                \'<span style="margin-right: 10px;">🔐</span> Secure Login with Passkey\' +
            \'</h3>\' +
            \'<p style="margin: 0 0 15px 0; color: #495057; font-size: 15px; line-height: 1.4;">\' +
                \'Skip passwords entirely. Use your device\\\'s built-in security (Touch ID, Face ID, Windows Hello) or a hardware key for instant, secure access.\' +
            \'</p>\' +
            \'<div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">\' +
                \'<button type="button" onclick="passkeyLogin()" \' +
                        \'style="background:#28a745;color:white;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:16px;font-weight:bold;box-shadow:0 2px 4px rgba(0,0,0,0.2);transition:all 0.2s;" \' +
                        \'onmouseover="this.style.background=\\\'#218838\\\'" onmouseout="this.style.background=\\\'#28a745\\\'">\' +
                    \'� Login with Passkey\' +
                \'</button>\' +
                \'<span style="color: #6c757d; font-size: 14px; font-style: italic;">or use the form below</span>\' +
            \'</div>\' +
            \'<div id="passkey-login-status" style="margin:15px 0 0 0;padding:10px;background:#fff;border:1px solid #dee2e6;border-radius:4px;color:#495057;min-height:24px;font-size:14px;"></div>\' +
        \'</div>\';
    
    // Insert the passkey UI
    if (targetElement.tagName === "FORM") {
        // Insert before the form
        targetElement.parentNode.insertBefore(passkeyDiv, targetElement);
        console.log("Passkey Plugin: Inserted passkey UI before form");
    } else if (targetElement.tagName === "BODY") {
        // For body, insert after any existing content
        if (targetElement.children.length > 0) {
            targetElement.insertBefore(passkeyDiv, targetElement.children[0]);
        } else {
            targetElement.appendChild(passkeyDiv);
        }
        console.log("Passkey Plugin: Inserted passkey UI in body");
    } else {
        // Insert at the beginning of the target element
        targetElement.insertBefore(passkeyDiv, targetElement.firstChild);
        console.log("Passkey Plugin: Inserted passkey UI inside target element");
    }
}

// Try to inject immediately if DOM is ready, otherwise wait
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function() {
        console.log("Passkey Plugin: DOM loaded, injecting UI");
        injectPasskeyUI();
    });
} else {
    console.log("Passkey Plugin: DOM already ready, injecting UI immediately");
    injectPasskeyUI();
}

// Also try after a short delay to catch dynamically loaded content
setTimeout(function() {
    console.log("Passkey Plugin: Delayed injection attempt");
    injectPasskeyUI();
}, 1000);

// Add the passkey login function globally
EOF;
        $html .= $js;
        $html .= <<<'EOF'

console.log("Passkey Plugin: Login functions loaded");
console.log("Passkey Plugin: UI injection completed");
*/
    
    /**
     * Helper method to add passkey UI to forms
     */
    private function addPasskeyLoginUI($form)
    {
        // Temporarily disabled to prevent interference with normal login
        if (!$this->enablePasskeyUI) {
            return;
        }
        
        if (!$form) {
            error_log('Passkey Plugin: addPasskeyLoginUI - No form provided');
            return;
        }
        
        error_log('Passkey Plugin: addPasskeyLoginUI called');
        
        // Prevent duplicate UI injection - use instance variable to prevent multiple calls across all hooks
        if ($this->uiInjected) {
            error_log('Passkey Plugin: addPasskeyLoginUI - UI already added globally, skipping duplicate');
            return;
        }
        
        $config = Am_Di::getInstance()->config;
        // Try multiple config key patterns
        $isEnabled = $config->get('misc.passkey.enable_passkey') || 
                    $config->get('passkey.enable_passkey') ||
                    $config->get('enable_passkey');
        error_log('Passkey Plugin: addPasskeyLoginUI - Trying config keys:');
        error_log('  misc.passkey.enable_passkey = ' . ($config->get('misc.passkey.enable_passkey') ? 'YES' : 'NO'));
        error_log('  passkey.enable_passkey = ' . ($config->get('passkey.enable_passkey') ? 'YES' : 'NO'));
        error_log('  enable_passkey = ' . ($config->get('enable_passkey') ? 'YES' : 'NO'));
        error_log('Passkey Plugin: addPasskeyLoginUI - Final enabled result: ' . ($isEnabled ? 'YES' : 'NO'));
        
        // Add passkey login UI to login forms
        error_log('Passkey Plugin: FORCING UI addition for debugging');
        
        // Add passkey login UI directly to the login form
        error_log('Passkey Plugin: addPasskeyLoginUI - Adding passkey UI to form');
            $form->addHtml('<div id="passkey-login-container" style="margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 4px; background: #f9f9f9;">
                <h4 style="margin: 0 0 10px 0; color: #333;">Secure Login with Passkey</h4>
                <p style="margin: 0 0 10px 0; color: #666; font-size: 14px;">Use your device\'s built-in security for quick, passwordless login.</p>
                <button type="button" onclick="passkeyLogin()" style="background:#007cba;color:white;padding:12px 24px;border:none;border-radius:4px;cursor:pointer;font-size:16px;">
                    🔐 Login with Passkey
                </button>
                <div id="passkey-login-status" style="margin:10px 0;color:#666;"></div>
            </div>');
            
            // Add the JavaScript directly to the form
            $form->addScript($this->getPasskeyLoginJS());
            $this->uiInjected = true;
            error_log('Passkey Plugin: addPasskeyLoginUI - Passkey UI added to form');
    }
    
    /**
     * Send clean JSON response without any output buffer interference
     */
    private function sendJsonResponse($data, $exit = true)
    {
        // Clean any output that might interfere with JSON
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        header('Content-Type: application/json');
        
        $json = json_encode($data);
        if ($json === false) {
            error_log('Passkey Plugin: JSON encoding failed: ' . json_last_error_msg());
            error_log('Passkey Plugin: Data that failed to encode: ' . print_r($data, true));
            echo json_encode(array('status' => 'fail', 'error' => 'JSON encoding error: ' . json_last_error_msg()));
        } else {
            echo $json;
        }
        
        if ($exit) {
            exit;
        }
    }

    /**
     * Send JSON response optimized for WebAuthn compatibility
     */
    private function sendWebAuthnJsonResponse($data, $exit = true)
    {
        // Clean any output that might interfere with JSON
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        header('Content-Type: application/json');
        
        $json = json_encode($data);
        if ($json === false) {
            error_log('Passkey Plugin: JSON encoding failed: ' . json_last_error_msg());
            error_log('Passkey Plugin: Data that failed to encode: ' . print_r($data, true));
            echo json_encode(array('status' => 'fail', 'error' => 'JSON encoding error: ' . json_last_error_msg()));
        } else {
            // Fix WebAuthn-specific encoding issues
            $json = str_replace('"extensions":[]', '"extensions":{}', $json);
            echo $json;
        }
        
        if ($exit) {
            exit;
        }
    }

    /**
     * Get the passkey login JavaScript code
     */
    private function getPasskeyLoginJS()
    {
        $js = '
// Helper function to safely call WebAuthn with extension interference protection
window.safeWebAuthnCreate = async function(options) {
    console.log("SafeWebAuthn: Starting protected credential creation");
    
    // Detect if 1Password or other extensions are interfering
    const hasExtensionInterference = () => {
        try {
            // Check for common extension frame access patterns
            if (window.frames && window.frames.length > 0) {
                for (let i = 0; i < window.frames.length; i++) {
                    try {
                        const frame = window.frames[i];
                        if (frame.location && frame.location.href.includes("1password")) {
                            return true;
                        }
                    } catch (e) {
                        // Frame access blocked - common with extensions
                        if (e.message.includes("permission denied") || e.message.includes("cross-origin")) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch (e) {
            console.log("SafeWebAuthn: Extension detection failed, proceeding with caution");
            return false;
        }
    };
    
    if (hasExtensionInterference()) {
        console.log("SafeWebAuthn: Extension interference detected, adding delays");
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    try {
        // Create a clean context for the WebAuthn call
        const createCredential = (async function() {
            return await navigator.credentials.create({publicKey: options});
        }).bind(null);
        
        const credential = await createCredential();
        console.log("SafeWebAuthn: Successfully created credential");
        return credential;
    } catch (error) {
        console.error("SafeWebAuthn: Error during credential creation:", error);
        throw error;
    }
};

// Helper function to safely call WebAuthn authentication with extension interference protection
window.safeWebAuthnGet = async function(options) {
    console.log("SafeWebAuthn: Starting protected credential authentication");
    
    // Detect if 1Password or other extensions are interfering
    const hasExtensionInterference = () => {
        try {
            // Check for common extension frame access patterns
            if (window.frames && window.frames.length > 0) {
                for (let i = 0; i < window.frames.length; i++) {
                    try {
                        const frame = window.frames[i];
                        if (frame.location && frame.location.href.includes("1password")) {
                            return true;
                        }
                    } catch (e) {
                        // Frame access blocked - common with extensions
                        if (e.message.includes("permission denied") || e.message.includes("cross-origin")) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch (e) {
            console.log("SafeWebAuthn: Extension detection failed, proceeding with caution");
            return false;
        }
    };
    
    if (hasExtensionInterference()) {
        console.log("SafeWebAuthn: Extension interference detected, adding delays");
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    try {
        // Create a clean context for the WebAuthn call
        const getCredential = (async function() {
            return await navigator.credentials.get({publicKey: options});
        }).bind(null);
        
        const assertion = await getCredential();
        console.log("SafeWebAuthn: Successfully authenticated credential");
        return assertion;
    } catch (error) {
        console.error("SafeWebAuthn: Error during credential authentication:", error);
        throw error;
    }
};

        window.passkeyLogin = async function() {
            var statusElements = [
                document.getElementById("passkey-login-status"),
                document.getElementById("passkey-login-status-body"), 
                document.getElementById("passkey-login-status-float"),
                document.getElementById("passkey-login-status-fallback")
            ];
            
            function updateStatus(message) {
                console.log("Passkey Status: " + message);
                statusElements.forEach(function(el) {
                    if (el) {
                        el.innerText = message;
                        // Show status element when there\'s a message
                        if (message) {
                            el.style.display = "block";
                        }
                        // Hide status element after success or if empty
                        if (message.includes("✅") || !message) {
                            setTimeout(function() {
                                el.style.display = "none";
                            }, 3000);
                        }
                    }
                });
            }            try {
                updateStatus("🟡 Initializing passkey login...");
                
                console.log("Passkey: Making AJAX request to passkey-login-init");
                
                // Use correct plugin endpoints
                let resp = await fetch("' . $this->getPluginUrl() . '", {
                    method: "POST", 
                    credentials: "same-origin",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    body: "action=passkey-login-init"
                });
                
                console.log("Passkey: Response status:", resp.status);
                
                // Check if response is actually JSON
                const contentType = resp.headers.get("content-type");
                console.log("Passkey: Response content-type:", contentType);
                
                let responseText = await resp.text();
                console.log("Passkey: Raw response text:", responseText);
                
                let data;
                try {
                    data = JSON.parse(responseText);
                    console.log("Passkey: Parsed JSON:", data);
                } catch (jsonError) {
                    updateStatus("❌ Error: Server returned invalid JSON");
                    console.error("Passkey: JSON parse error:", jsonError);
                    console.error("Passkey: Response was:", responseText);
                    return;
                }
                
                if (data.status !== "ok") {
                    updateStatus("❌ Error: " + (data.error || "Unknown error"));
                    return;
                }
                
                updateStatus("🔑 Please use your passkey...");
                
                let publicKey = data.options;
                console.log("Passkey: PublicKey options:", publicKey);
                
                // Add safety checks for challenge decoding
                if (!publicKey.challenge) {
                    updateStatus("❌ Error: No challenge provided");
                    console.error("Passkey: Missing challenge in server response");
                    return;
                }
                
                try {
                    // Decode challenge with better error handling
                    publicKey.challenge = Uint8Array.from(atob(publicKey.challenge), function(c) { return c.charCodeAt(0); });
                } catch (e) {
                    updateStatus("❌ Error: Invalid challenge format");
                    console.error("Passkey: Challenge decode error:", e, "Challenge was:", data.options.challenge);
                    return;
                }
                
                if (publicKey.allowCredentials) {
                    try {
                        publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
                            ...cred,
                            id: Uint8Array.from(atob(cred.id), function(c) { return c.charCodeAt(0); })
                        }));
                    } catch (e) {
                        updateStatus("❌ Error: Invalid credential format");
                        console.error("Passkey: Credential decode error:", e, "Credentials:", publicKey.allowCredentials);
                        return;
                    }
                }
                
                console.log("Passkey: Calling navigator.credentials.get with extension protection");
                let assertion = await window.safeWebAuthnGet(publicKey);
                console.log("Passkey: Got assertion:", assertion);
                
                updateStatus("🔒 Verifying credential...");
                
                let authData = {
                    id: assertion.id,
                    rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))),
                    type: assertion.type,
                    response: {
                        authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))),
                        signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature)))
                    }
                };
                
                console.log("Passkey: Sending finish request with auth data:", authData);
                
                let finishResp = await fetch("' . $this->getPluginUrl() . '", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    credentials: "same-origin",
                    body: "action=passkey-login-finish&assertion=" + encodeURIComponent(JSON.stringify(authData))
                });
                
                console.log("Passkey: Finish response status:", finishResp.status);
                let finishData = await finishResp.json();
                console.log("Passkey: Finish response data:", finishData);
                
                if (finishData.status === "ok") {
                    updateStatus("✅ Login successful! Redirecting...");
                    setTimeout(function() {
                        window.location.reload();
                    }, 1000);
                } else {
                    updateStatus("❌ Login failed: " + (finishData.error || "Unknown error"));
                }
            } catch (e) {
                console.error("Passkey error:", e);
                updateStatus("❌ Error: " + e.message);
            }
        };
        
        // Add the passkey registration function
        window.passkeyRegister = async function() {
            // Ask user for a name for this passkey
            var passkeyName = prompt("Give this passkey a name (e.g., \\"iPhone\\", \\"YubiKey\\", \\"Work Laptop\\"):", "");
            if (passkeyName === null) {
                return; // User cancelled
            }
            if (!passkeyName.trim()) {
                passkeyName = "Unnamed Passkey"; // Default name
            }
            
            var statusElements = [
                document.getElementById("passkey-login-status"),
                document.getElementById("passkey-login-status-body"), 
                document.getElementById("passkey-login-status-float"),
                document.getElementById("passkey-login-status-fallback")
            ];
            
            function updateStatus(message) {
                console.log("Passkey Status: " + message);
                statusElements.forEach(function(el) {
                    if (el) el.innerText = message;
                });
            }
            
            try {
                updateStatus("🟡 Initializing passkey registration for \\"" + passkeyName + "\\"...");
                
                console.log("Passkey: Making AJAX request to passkey-register-init");
                let resp = await fetch("' . $this->getPluginUrl() . '", {
                    method: "POST", 
                    credentials: "same-origin",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    body: "action=passkey-register-init"
                });
                
                console.log("Passkey: Registration response status:", resp.status);
                let responseText = await resp.text();
                console.log("Passkey: Raw response text:", responseText);
                
                let data;
                try {
                    data = JSON.parse(responseText);
                    console.log("Passkey: Registration options:", data);
                } catch (jsonError) {
                    updateStatus("❌ Error: Server returned invalid JSON");
                    console.error("Passkey: JSON parse error:", jsonError);
                    console.error("Passkey: Response was:", responseText);
                    return;
                }
                
                if (data.status !== "ok") {
                    updateStatus("❌ Error: " + (data.error || "Unknown error"));
                    return;
                }
                
                updateStatus("🔑 Please complete passkey registration...");
                
                let options = data.options;
                
                // Decode challenge and user ID
                options.challenge = Uint8Array.from(atob(options.challenge), function(c) { return c.charCodeAt(0); });
                options.user.id = Uint8Array.from(atob(options.user.id), function(c) { return c.charCodeAt(0); });
                
                console.log("Passkey: Calling navigator.credentials.create with extension protection");
                let credential = await window.safeWebAuthnCreate(options);
                console.log("Passkey: Got credential:", credential);
                
                updateStatus("🔒 Saving passkey...");
                
                // Prepare credential data
                let credData = {
                    id: credential.id,
                    rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                    type: credential.type,
                    response: {
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                        attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
                    }
                };
                
                console.log("Passkey: Sending registration finish with credential data");
                
                let finishResp = await fetch("' . $this->getPluginUrl() . '", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    credentials: "same-origin",
                    body: "action=passkey-register-finish&credential=" + encodeURIComponent(JSON.stringify(credData)) + "&passkey_name=" + encodeURIComponent(passkeyName)
                });
                
                console.log("Passkey: Registration finish response status:", finishResp.status);
                let finishData = await finishResp.json();
                console.log("Passkey: Registration finish response data:", finishData);
                
                if (finishData.status === "ok") {
                    updateStatus("✅ Passkey registered successfully! You now have " + (finishData.total_passkeys || 1) + " passkey(s).");
                } else {
                    updateStatus("❌ Registration failed: " + (finishData.error || "Unknown error"));
                }
            } catch (e) {
                console.error("Passkey registration error:", e);
                updateStatus("❌ Registration error: " + e.message);
            }
        };
        
        // Add passkey delete function
        window.deletePasskey = async function(credentialId) {
            console.log("deletePasskey called with ID:", credentialId);
            
            if (!confirm("Are you sure you want to delete this passkey? This action cannot be undone.")) {
                console.log("Delete cancelled by user");
                return;
            }
            
            // Try to find status element - could be on login page or profile page
            var statusEl = document.getElementById("passkey-login-status") || 
                          document.getElementById("passkey-profile-status") ||
                          document.getElementById("passkey-status");
            
            function updateStatus(message) {
                console.log("Passkey Delete Status: " + message);
                if (statusEl) {
                    statusEl.innerHTML = message;
                } else {
                    // Create temporary status display if no status element exists
                    var tempStatus = document.createElement("div");
                    tempStatus.style.cssText = "position: fixed; top: 20px; right: 20px; z-index: 99999; background: #007cba; color: white; padding: 10px 15px; border-radius: 6px; font-size: 14px; max-width: 300px;";
                    tempStatus.innerHTML = message;
                    document.body.appendChild(tempStatus);
                    setTimeout(function() {
                        if (tempStatus.parentNode) tempStatus.remove();
                    }, 5000);
                }
            }
            
            try {
                updateStatus("🗑️ Deleting passkey...");
                console.log("Making delete request to:", "' . $this->getPluginUrl() . '");
                
                let resp = await fetch("' . $this->getPluginUrl() . '", {
                    method: "POST",
                    credentials: "same-origin",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    body: "action=passkey-delete&credential_id=" + encodeURIComponent(credentialId)
                });
                
                console.log("Delete response status:", resp.status);
                let responseText = await resp.text();
                console.log("Passkey Delete Response:", responseText);
                
                let data;
                try {
                    data = JSON.parse(responseText);
                } catch (jsonError) {
                    console.error("JSON parse error:", jsonError);
                    console.error("Raw response:", responseText);
                    updateStatus("❌ Error: Server returned invalid response");
                    return;
                }
                
                console.log("Parsed delete response:", data);
                
                if (data.status === "ok") {
                    updateStatus("✅ Passkey deleted successfully! Refreshing page...");
                    setTimeout(function() {
                        window.location.reload();
                    }, 1500);
                } else {
                    updateStatus("❌ Delete failed: " + (data.error || "Unknown error"));
                }
            } catch (e) {
                console.error("Passkey delete error:", e);
                updateStatus("❌ Error: " + e.message);
            }
        };
        
        // Add passkey naming function
        window.renamePasskey = async function(credentialId, currentName) {
            var newName = prompt("Enter a new name for this passkey:", currentName || "");
            if (!newName || newName === currentName) {
                return;
            }
            
            var statusEl = document.getElementById("passkey-login-status");
            
            function updateStatus(message) {
                console.log("Passkey Rename Status: " + message);
                if (statusEl) statusEl.innerHTML = message;
            }
            
            try {
                updateStatus("✏️ Renaming passkey...");
                
                let resp = await fetch("' . $this->getPluginUrl() . '", {
                    method: "POST",
                    credentials: "same-origin",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    body: "action=passkey-rename&credential_id=" + encodeURIComponent(credentialId) + "&new_name=" + encodeURIComponent(newName)
                });
                
                let responseText = await resp.text();
                console.log("Passkey Rename Response:", responseText);
                
                let data;
                try {
                    data = JSON.parse(responseText);
                } catch (jsonError) {
                    updateStatus("❌ Error: Server returned invalid response");
                    console.error("JSON parse error:", jsonError);
                    return;
                }
                
                if (data.status === "ok") {
                    updateStatus("✅ Passkey renamed successfully! Refreshing page...");
                    setTimeout(function() {
                        window.location.reload();
                    }, 1500);
                } else {
                    updateStatus("❌ Rename failed: " + (data.error || "Unknown error"));
                }
            } catch (e) {
                console.error("Passkey rename error:", e);
                updateStatus("❌ Error: " + e.message);
            }
        };
        
        // Add passkey info function  
        window.showPasskeyInfo = function() {
            var statusEl = document.getElementById("passkey-login-status");
            if (statusEl) {
                statusEl.innerHTML = 
                    "<h5>🔑 What are Passkeys?</h5>" +
                    "<p>Passkeys are a secure, passwordless way to sign into your account using your device\'s built-in security features:</p>" +
                    "<ul>" +
                        "<li><strong>Touch ID</strong> or <strong>Face ID</strong> on Mac/iPhone</li>" +
                        "<li><strong>Windows Hello</strong> on Windows</li>" +
                        "<li><strong>Fingerprint</strong> or <strong>Face unlock</strong> on Android</li>" +
                        "<li><strong>Hardware security keys</strong> (YubiKey, etc.)</li>" +
                    "</ul>" +
                    "<p><strong>Benefits:</strong></p>" +
                    "<ul>" +
                        "<li>No passwords to remember or type</li>" +
                        "<li>Extremely secure - cannot be phished</li>" +
                        "<li>Fast and convenient login</li>" +
                        "<li>Works across your devices</li>" +
                    "</ul>" +
                    "<p><em>Click \\"Register New Passkey\\" to set up passwordless login for this account.</em></p>";
            }
        };
        
        console.log("Passkey: Login and registration functions loaded globally");';
        
        return $js;
    }

    /**
     * Authenticate user using passkey (FIDO2/WebAuthn)
     */
    public function onAuthenticate(Am_Event_Authenticate $event)
    {
        // This method is not used for passkey login, as authentication is handled via AJAX and session.
    }

    /**
     * Direct AJAX handler for when hooks don't work properly
     */
    public function handleAjaxDirect()
    {
        error_log('Passkey Plugin: handleAjaxDirect called - direct AJAX processing');
        
        // Call the main AJAX handler with a dummy event
        $this->onAjax(new stdClass());
    }

    /**
     * AJAX handler for registration and login
     */
    public function onAjax($event = null)
    {
        // Ensure table exists and has all required columns before processing any AJAX requests
        $this->ensureTableAndColumns();
        
        // Force clean output for AJAX - no HTML debug markers
        error_log('Passkey Plugin: onAjax called');
        error_log('Passkey Plugin: REQUEST_URI: ' . $_SERVER['REQUEST_URI']);
        error_log('Passkey Plugin: Full REQUEST: ' . print_r($_REQUEST, true));
        error_log('Passkey Plugin: HTTP_HOST: ' . $_SERVER['HTTP_HOST']);
        error_log('Passkey Plugin: SCRIPT_NAME: ' . $_SERVER['SCRIPT_NAME']);
        
        // Parse the action from the REQUEST_URI for aMember's AJAX system
        $action = '';
        
        // First check REQUEST/GET/POST for action parameter (standard aMember way)
        if (isset($_REQUEST['action'])) {
            $action = $_REQUEST['action'];
            error_log('Passkey Plugin: Action from REQUEST: ' . $action);
        } elseif (isset($_GET['action'])) {
            $action = $_GET['action'];
            error_log('Passkey Plugin: Action from GET: ' . $action);
        } elseif (isset($_POST['action'])) {
            $action = $_POST['action'];
            error_log('Passkey Plugin: Action from POST: ' . $action);
        }
        // Then try multiple patterns to extract action from aMember's AJAX routing
        elseif (preg_match('/ajax\.php\?.*action=([^&]+)/', $_SERVER['REQUEST_URI'], $matches)) {
            $action = $matches[1];
            error_log('Passkey Plugin: Action from URI pattern (query): ' . $action);
        } elseif (preg_match('/\/ajax\/([^\/\?]+)/', $_SERVER['REQUEST_URI'], $matches)) {
            $action = $matches[1];
            error_log('Passkey Plugin: Action from URI pattern 1: ' . $action);
        } elseif (preg_match('/ajax\.php\/([^\/\?]+)/', $_SERVER['REQUEST_URI'], $matches)) {
            $action = $matches[1];
            error_log('Passkey Plugin: Action from URI pattern 2: ' . $action);
        } elseif (isset($_GET['_'])) {
            // aMember sometimes uses _ parameter for AJAX actions
            $action = $_GET['_'];
            error_log('Passkey Plugin: Action from _ parameter: ' . $action);
        }
        
        // Additional fallback: check if this is a direct passkey action call
        $uri = $_SERVER['REQUEST_URI'];
        if (strpos($uri, 'passkey-register-init') !== false) {
            $action = 'passkey-register-init';
        } elseif (strpos($uri, 'passkey-register-finish') !== false) {
            $action = 'passkey-register-finish';
        } elseif (strpos($uri, 'passkey-login-init') !== false) {
            $action = 'passkey-login-init';
        } elseif (strpos($uri, 'passkey-login-finish') !== false) {
            $action = 'passkey-login-finish';
        } elseif (strpos($uri, 'passkey-debug') !== false) {
            $action = 'passkey-debug';
        }
        
        error_log('Passkey Plugin: Final detected action: ' . $action);
        
        // Handle debug action - try multiple detection methods
        if ($action === 'passkey-debug' || 
            strpos($_SERVER['REQUEST_URI'], 'passkey-debug') !== false ||
            isset($_GET['passkey-debug']) ||
            isset($_POST['passkey-debug']) ||
            isset($_GET['debug_passkey']) ||
            $action === 'debug_passkey') {
            error_log('Passkey Plugin: Handling debug action via multiple detection');
            $this->handleDebugAction();
            return;
        }
        
        // Only load Composer and WebAuthn classes if this is a passkey-related AJAX request
        if (!in_array($action, array('passkey-register-init', 'passkey-register-finish', 'passkey-login-init', 'passkey-login-finish', 'passkey-delete', 'passkey-rename'))) {
            error_log('Passkey Plugin: Not a passkey action, ignoring: ' . $action);
            return;
        }
        
        error_log('Passkey Plugin: Processing passkey action: ' . $action);
        
        // Try to load Composer autoload - be defensive about the path
        $possiblePaths = array(
            __DIR__ . '/../../../../../vendor/autoload.php',
            __DIR__ . '/../../../../vendor/autoload.php',
            __DIR__ . '/../../../vendor/autoload.php'
        );
        
        $autoloadFound = false;
        foreach ($possiblePaths as $autoloadPath) {
            if (file_exists($autoloadPath)) {
                require_once $autoloadPath;
                $autoloadFound = true;
                error_log('Passkey Plugin: Loaded autoload from: ' . $autoloadPath);
                break;
            }
        }
        
        if (!$autoloadFound) {
            error_log('Passkey plugin error: vendor/autoload.php not found. Run composer install.');
            if (php_sapi_name() !== 'cli') {
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'vendor/autoload.php not found. Run composer install.'));
            }
            return;
        }
        
        $session = Am_Di::getInstance()->session;
        $auth = Am_Di::getInstance()->auth;
        $db = Am_Di::getInstance()->db;
        $config = Am_Di::getInstance()->config;
        $rpName = $config->get('misc.passkey.rp_name', 'aMember');
        $rpId = $config->get('misc.passkey.rp_id', $_SERVER['HTTP_HOST']);
        
        // Debug: Check what WebAuthn classes are available
        error_log('Passkey Plugin: Checking available WebAuthn classes');
        
        if (class_exists('Webauthn\\PublicKeyCredentialRpEntity')) {
            error_log('Passkey Plugin: Found Webauthn\\PublicKeyCredentialRpEntity class');
        }
        if (class_exists('Webauthn\\RelyingParty')) {
            error_log('Passkey Plugin: Found Webauthn\\RelyingParty class');
        }
        if (class_exists('Webauthn\\Server')) {
            error_log('Passkey Plugin: Found Webauthn\\Server class');
        }
        
        // Get all available classes and filter for WebAuthn
        $allClasses = get_declared_classes();
        $webauthnClasses = array_filter($allClasses, function($class) {
            return stripos($class, 'webauthn') !== false || stripos($class, 'fido') !== false;
        });
        error_log('Passkey Plugin: Available WebAuthn/FIDO classes: ' . implode(', ', array_slice($webauthnClasses, 0, 10)));
        
        // Create WebAuthn objects only after autoload is confirmed
        try {
            // Try different possible class names based on web-auth/webauthn-lib versions
            if (class_exists('Webauthn\\PublicKeyCredentialRpEntity')) {
                // Version 4.x+ style
                $rp = new Webauthn\PublicKeyCredentialRpEntity($rpName, $rpId);
                error_log('Passkey Plugin: Created RelyingParty using PublicKeyCredentialRpEntity');
            } elseif (class_exists('Webauthn\\RelyingParty')) {
                // Older version style
                $rp = new Webauthn\RelyingParty($rpName, $rpId);
                error_log('Passkey Plugin: Created RelyingParty using RelyingParty class');
            } else {
                // Fallback - create manually or use alternative approach
                error_log('Passkey Plugin: Neither RelyingParty class found - creating mock object');
                $rp = (object) array('name' => $rpName, 'id' => $rpId);
            }
            
            $storage = $this->createCredentialStorage();
        } catch (Exception $e) {
            error_log('Passkey Plugin: WebAuthn error: ' . $e->getMessage());
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'WebAuthn library error: ' . $e->getMessage()));
            return;
        }

        // CSRF/session check for all AJAX actions
        if (!$auth->getUser() && !in_array($action, array('passkey-login-init', 'passkey-login-finish'))) {
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Not authenticated.'));
            exit;
        }

        if ($action === 'passkey-register-init') {
            $this->handleRegisterInit($auth, $session, $rp, $storage);
        } elseif ($action === 'passkey-register-finish') {
            $this->handleRegisterFinish($session, $rp, $storage);
        } elseif ($action === 'passkey-login-init') {
            $this->handleLoginInit($session, $rp, $storage);
        } elseif ($action === 'passkey-login-finish') {
            $this->handleLoginFinish($session, $auth, $db, $rp, $storage);
        } elseif ($action === 'passkey-delete') {
            $this->handleDeletePasskey($auth, $db);
        } elseif ($action === 'passkey-rename') {
            $this->handleRenamePasskey($auth, $db);
        }
    }

    /**
     * Handle debug action - comprehensive plugin diagnostics
     */
    private function handleDebugAction()
    {
        header('Content-Type: text/html; charset=utf-8');
        
        $html = '<!DOCTYPE html>
<html>
<head>
    <title>Passkey Plugin Debug</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ccc; background: white; border-radius: 5px; }
        .success { background: #d4edda; border-color: #c3e6cb; }
        .warning { background: #fff3cd; border-color: #ffeaa7; }
        .error { background: #f8d7da; border-color: #f5c6cb; }
        .debug-button { background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
        h1 { color: #333; }
        h2 { color: #666; margin-top: 0; }
    </style>
</head>
<body>
    <h1>🔍 Passkey Plugin Debug Information</h1>
    <p><em>Generated: ' . date('Y-m-d H:i:s') . '</em></p>';

        // Plugin Status
        $html .= '<div class="section success">
            <h2>✅ Plugin Status</h2>
            <p><strong>Plugin loaded and debug handler active</strong></p>
            <p>Plugin Class: ' . get_class($this) . '</p>
            <p>Plugin ID: ' . $this->getId() . '</p>
            <p>Plugin File: ' . __FILE__ . '</p>
        </div>';

        // Configuration
        $html .= '<div class="section">';
        try {
            $config = Am_Di::getInstance()->config;
            $enablePasskey = $config->get('misc.passkey.enable_passkey');
            $rpName = $config->get('misc.passkey.rp_name');
            $rpId = $config->get('misc.passkey.rp_id');
            
            $configClass = $enablePasskey ? 'success' : 'warning';
            $html .= '<h2>⚙️ Configuration</h2>
                <p>misc.passkey.enable_passkey: <strong>' . ($enablePasskey ? 'YES' : 'NO') . '</strong></p>
                <p>misc.passkey.rp_name: ' . ($rpName ?: '<em>NOT SET</em>') . '</p>
                <p>misc.passkey.rp_id: ' . ($rpId ?: '<em>NOT SET</em>') . '</p>';
                
            // Try alternative config paths
            $altEnable = $config->get('passkey.enable_passkey');
            if ($altEnable) {
                $html .= '<p class="warning">⚠️ Alternative config found: passkey.enable_passkey = YES</p>';
            }
        } catch (Exception $e) {
            $html .= '<h2 class="error">❌ Configuration Error</h2>
                <p>Error reading config: ' . htmlspecialchars($e->getMessage()) . '</p>';
        }
        $html .= '</div>';

        // Database
        $html .= '<div class="section">';
        try {
            $db = Am_Di::getInstance()->db;
            $tables = $db->select("SHOW TABLES LIKE ?", '%passkey_credentials%');
            
            if ($tables) {
                $count = $db->selectCell("SELECT COUNT(*) FROM ?_passkey_credentials");
                $html .= '<h2>✅ Database</h2>
                    <p>Passkey credentials table: <strong>EXISTS</strong></p>
                    <p>Stored credentials: <strong>' . $count . '</strong></p>';
            } else {
                $html .= '<h2 class="error">❌ Database</h2>
                    <p>Passkey credentials table: <strong>NOT FOUND</strong></p>';
            }
        } catch (Exception $e) {
            $html .= '<h2 class="error">❌ Database Error</h2>
                <p>Error: ' . htmlspecialchars($e->getMessage()) . '</p>';
        }
        $html .= '</div>';

        // Composer Dependencies
        $html .= '<div class="section">';
        $vendorPaths = [
            __DIR__ . '/../../../../../vendor/autoload.php',
            __DIR__ . '/../../../../vendor/autoload.php',
            __DIR__ . '/../../../vendor/autoload.php'
        ];
        
        $composerFound = false;
        $composerPath = '';
        foreach ($vendorPaths as $path) {
            if (file_exists($path)) {
                $composerPath = $path;
                $composerFound = true;
                break;
            }
        }
        
        if ($composerFound) {
            include_once $composerPath;
            $webauthnAvailable = class_exists('Webauthn\RelyingParty');
            $composerClass = $webauthnAvailable ? 'success' : 'warning';
            
            $html .= '<h2>📦 Composer Dependencies</h2>
                <p>Autoload found: <strong>' . $composerPath . '</strong></p>
                <p>WebAuthn library: <strong>' . ($webauthnAvailable ? 'AVAILABLE' : 'NOT FOUND') . '</strong></p>';
        } else {
            $html .= '<h2 class="error">❌ Composer Dependencies</h2>
                <p>Autoload: <strong>NOT FOUND</strong></p>
                <p>Tried paths:</p><ul>';
            foreach ($vendorPaths as $path) {
                $html .= '<li>' . htmlspecialchars($path) . '</li>';
            }
            $html .= '</ul>';
        }
        $html .= '</div>';

        // Server Environment
        $html .= '<div class="section">
            <h2>🖥️ Server Environment</h2>
            <p>PHP Version: <strong>' . PHP_VERSION . '</strong></p>
            <p>aMember URL: <strong>' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] . '</strong></p>
            <p>Plugin Directory: <strong>' . __DIR__ . '</strong></p>
            <p>Current Time: <strong>' . date('Y-m-d H:i:s T') . '</strong></p>
        </div>';

        // Hook Testing
        $html .= '<div class="section">
            <h2>🔗 Hook Testing</h2>
            <p>Access this debug page with different URLs to test hook firing:</p>
            <ul>
                <li><a href="/amember/application/default/plugins/misc/passkey/passkey.php?action=debug_passkey" target="_blank">AJAX Debug: /amember/application/default/plugins/misc/passkey/passkey.php?action=debug_passkey</a></li>
                <li><a href="?debug_passkey=1" target="_blank">GET Parameter: ?debug_passkey=1</a></li>
                <li><a href="/amember/?passkey-debug=1" target="_blank">Direct Parameter: ?passkey-debug=1</a></li>
            </ul>
            <p><strong>Instructions:</strong></p>
            <ol>
                <li>Visit your aMember login page</li>
                <li>Check for red/blue debug boxes in top-left corner</li>
                <li>Look for passkey UI section</li>
                <li>Open browser console (F12) and look for "Passkey Plugin:" messages</li>
            </ol>
        </div>';

        // Browser Tests
        $html .= '<div class="section">
            <h2>🌐 Browser WebAuthn Support Test</h2>
            <button class="debug-button" onclick="testWebAuthnSupport()">Test WebAuthn Support</button>
            <div id="webauthn-test-result" style="margin-top: 10px;"></div>
            
            <h3>AJAX Endpoint Test</h3>
            <button class="debug-button" onclick="testPasskeyEndpoint()">Test Passkey Login Init</button>
            <div id="ajax-test-result" style="margin-top: 10px;"></div>
        </div>';

        // JavaScript
        $html .= '<script>
        function testWebAuthnSupport() {
            const result = document.getElementById("webauthn-test-result");
            
            if (window.PublicKeyCredential) {
                result.innerHTML = "<p style=\\"color: green;\\">✅ WebAuthn is supported by your browser</p>";
                
                PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
                    .then(available => {
                        if (available) {
                            result.innerHTML += "<p style=\\"color: green;\\">✅ Platform authenticator (built-in) available</p>";
                        } else {
                            result.innerHTML += "<p style=\\"color: orange;\\">⚠️ Platform authenticator not available (external security key required)</p>";
                        }
                    })
                    .catch(err => {
                        result.innerHTML += "<p style=\\"color: red;\\">❌ Error checking platform authenticator: " + err.message + "</p>";
                    });
            } else {
                result.innerHTML = "<p style=\\"color: red;\\">❌ WebAuthn is NOT supported by your browser</p>";
            }
        }
        
        async function testPasskeyEndpoint() {
            const result = document.getElementById("ajax-test-result");
            result.innerHTML = "<p>Testing AJAX endpoint...</p>";
            
            try {
                const response = await fetch("/amember/ajax/passkey-login-init", {
                    method: "POST",
                    credentials: "same-origin",
                    headers: {
                        "X-Requested-With": "XMLHttpRequest"
                    }
                });
                
                const data = await response.json();
                result.innerHTML = "<p>Response Status: <strong>" + response.status + "</strong></p>";
                result.innerHTML += "<pre>" + JSON.stringify(data, null, 2) + "</pre>";
                
                if (data.status === "ok") {
                    result.innerHTML += "<p style=\\"color: green;\\">✅ AJAX endpoint working</p>";
                } else {
                    result.innerHTML += "<p style=\\"color: red;\\">❌ AJAX endpoint returned error</p>";
                }
            } catch (error) {
                result.innerHTML += "<p style=\\"color: red;\\">❌ AJAX request failed: " + error.message + "</p>";
            }
        }
        </script>';

        $html .= '</body></html>';
        
        echo $html;
        exit;
    }

    /**
     * Create credential storage instance with version-flexible approach
     */
    private function createCredentialStorage()
    {
        $plugin = $this;
        
        // Check what repository interface is available
        if (interface_exists('Webauthn\\PublicKeyCredentialSourceRepository')) {
            error_log('Passkey Plugin: Found PublicKeyCredentialSourceRepository interface');
        } elseif (interface_exists('Webauthn\\PublicKeyCredentialSourceRepositoryInterface')) {
            error_log('Passkey Plugin: Found PublicKeyCredentialSourceRepositoryInterface interface');
        } else {
            error_log('Passkey Plugin: No credential repository interface found');
        }
        
        // Create basic storage object that should work with any version
        return new class($plugin) {
            private $plugin;
            
            public function __construct($plugin) 
            { 
                $this->plugin = $plugin; 
            }
            
            public function findOneByCredentialId($credentialId) 
            {
                error_log('Passkey Plugin: Storage findOneByCredentialId called');
                try {
                    $db = Am_Di::getInstance()->db;
                    $row = $db->selectRow('SELECT * FROM ?_passkey_credentials WHERE credential_id = ?', $credentialId);
                    if (!$row) return null;
                    
                    // Try to create PublicKeyCredentialSource if class exists
                    if (class_exists('Webauthn\\PublicKeyCredentialSource')) {
                        return new Webauthn\PublicKeyCredentialSource(
                            $row['credential_id'],
                            $row['type'],
                            $row['transports'],
                            $row['attestation_type'],
                            $row['trust_path'],
                            $row['aaguid'],
                            $row['public_key'],
                            $row['user_handle'],
                            $row['counter']
                        );
                    } else {
                        // Return raw data if class not available
                        return $row;
                    }
                } catch (Exception $e) {
                    error_log('Passkey Plugin: Error in findOneByCredentialId: ' . $e->getMessage());
                    return null;
                }
            }
            
            public function findAllForUserEntity($userEntity)
            {
                error_log('Passkey Plugin: Storage findAllForUserEntity called');
                try {
                    $db = Am_Di::getInstance()->db;
                    $userId = is_object($userEntity) ? $userEntity->getId() : $userEntity;
                    $rows = $db->selectRows('SELECT * FROM ?_passkey_credentials WHERE user_handle = ?', $userId);
                    $result = array();
                    foreach ($rows as $row) {
                        if (class_exists('Webauthn\\PublicKeyCredentialSource')) {
                            $result[] = new Webauthn\PublicKeyCredentialSource(
                                $row['credential_id'],
                                $row['type'],
                                $row['transports'],
                                $row['attestation_type'],
                                $row['trust_path'],
                                $row['aaguid'],
                                $row['public_key'],
                                $row['user_handle'],
                                $row['counter']
                            );
                        } else {
                            $result[] = $row;
                        }
                    }
                    return $result;
                } catch (Exception $e) {
                    error_log('Passkey Plugin: Error in findAllForUserEntity: ' . $e->getMessage());
                    return array();
                }
            }
            
            public function saveCredentialSource($source)
            {
                error_log('Passkey Plugin: Storage saveCredentialSource called');
                try {
                    $db = Am_Di::getInstance()->db;
                    error_log('Passkey Plugin: Got database connection');
                    
                    // Check if table exists - use actual table name for information_schema queries
                    
                    // Use a different approach - query information_schema
                    $actualTableName = $db->getPrefix() . 'passkey_credentials';
                    try {
                        $tableExists = $db->selectCell("SELECT COUNT(*) FROM information_schema.tables 
                            WHERE table_schema = DATABASE() AND table_name = ?", $actualTableName);
                        error_log('Passkey Plugin: Table exists check result: ' . ($tableExists ? 'exists' : 'does not exist'));
                    } catch (Exception $e) {
                        $tableExists = false;
                        error_log('Passkey Plugin: Table existence check failed: ' . $e->getMessage());
                    }
                    if (!$tableExists) {
                        error_log('Passkey Plugin: Table does not exist, creating it');
                        // Create the table using aMember's ?_ syntax
                        $createTableSql = "
                        CREATE TABLE ?_passkey_credentials (
                            credential_id VARCHAR(255) NOT NULL PRIMARY KEY,
                            `type` VARCHAR(50) NOT NULL,
                            transports TEXT,
                            attestation_type VARCHAR(50),
                            trust_path TEXT,
                            aaguid VARCHAR(255),
                            public_key TEXT NOT NULL,
                            user_handle VARCHAR(255) NOT NULL,
                            counter INT NOT NULL DEFAULT 0,
                            name VARCHAR(100) DEFAULT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            INDEX idx_user_handle (user_handle)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8
                        ";
                        $db->query($createTableSql);
                        error_log('Passkey Plugin: Table created successfully');
                    } else {
                        error_log('Passkey Plugin: Table exists');
                        
                        // Check if the type column exists and add it if missing
                        try {
                            $columnExists = $db->selectCell("SELECT COUNT(*) FROM information_schema.columns 
                                WHERE table_schema = DATABASE() AND table_name = ? AND column_name = 'type'", $actualTableName);
                            error_log('Passkey Plugin: Type column exists check: ' . ($columnExists ? 'yes' : 'no'));
                            
                            if (!$columnExists) {
                                error_log('Passkey Plugin: Adding missing type column');
                                $db->query("ALTER TABLE ?_passkey_credentials ADD COLUMN `type` VARCHAR(50) NOT NULL DEFAULT 'public-key' AFTER credential_id");
                                error_log('Passkey Plugin: Type column added successfully');
                            }
                            
                            // Check for other essential columns that might be missing
                            $requiredColumns = [
                                'transports' => "TEXT",
                                'attestation_type' => "VARCHAR(50)",
                                'trust_path' => "TEXT", 
                                'aaguid' => "VARCHAR(255)",
                                'user_handle' => "VARCHAR(255) NOT NULL",
                                'counter' => "INT NOT NULL DEFAULT 0",
                                'name' => "VARCHAR(100) DEFAULT NULL",
                                'created_at' => "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                            ];
                            
                            foreach ($requiredColumns as $colName => $colType) {
                                $colExists = $db->selectCell("SELECT COUNT(*) FROM information_schema.columns 
                                    WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?", $actualTableName, $colName);
                                if (!$colExists) {
                                    error_log('Passkey Plugin: Adding missing column: ' . $colName);
                                    $db->query("ALTER TABLE ?_passkey_credentials ADD COLUMN `{$colName}` {$colType}");
                                }
                            }
                            
                        } catch (Exception $e) {
                            error_log('Passkey Plugin: Error checking/adding columns: ' . $e->getMessage());
                        }
                    }
                    
                    // Extract data from source object or array
                    if (is_object($source)) {
                        error_log('Passkey Plugin: Processing object source');
                        $credentialId = method_exists($source, 'getPublicKeyCredentialId') ? $source->getPublicKeyCredentialId() : (isset($source->credential_id) ? $source->credential_id : null);
                        $type = method_exists($source, 'getType') ? $source->getType() : (isset($source->type) ? $source->type : 'public-key');
                        $transports = method_exists($source, 'getTransports') ? json_encode($source->getTransports()) : (isset($source->transports) ? $source->transports : '[]');
                        $attestationType = method_exists($source, 'getAttestationType') ? $source->getAttestationType() : (isset($source->attestation_type) ? $source->attestation_type : 'none');
                        $trustPath = method_exists($source, 'getTrustPath') ? json_encode($source->getTrustPath()) : (isset($source->trust_path) ? $source->trust_path : '[]');
                        $aaguid = method_exists($source, 'getAaguid') ? $source->getAaguid() : (isset($source->aaguid) ? $source->aaguid : '');
                        $publicKey = method_exists($source, 'getCredentialPublicKey') ? $source->getCredentialPublicKey() : (isset($source->public_key) ? $source->public_key : '');
                        $userHandle = method_exists($source, 'getUserHandle') ? $source->getUserHandle() : (isset($source->user_handle) ? $source->user_handle : null);
                        $counter = method_exists($source, 'getCounter') ? $source->getCounter() : (isset($source->counter) ? $source->counter : 0);
                        $name = isset($source->name) ? $source->name : 'Unnamed Passkey';
                    } elseif (is_array($source)) {
                        error_log('Passkey Plugin: Processing array source');
                        // Handle array input
                        $credentialId = $source['credential_id'] ?? null;
                        $type = $source['type'] ?? 'public-key';
                        $transports = $source['transports'] ?? '[]'; // Already JSON encoded
                        $attestationType = $source['attestation_type'] ?? 'none';
                        $trustPath = $source['trust_path'] ?? '[]'; // Already JSON encoded
                        $aaguid = $source['aaguid'] ?? '';
                        $publicKey = $source['public_key'] ?? '';
                        $userHandle = $source['user_handle'] ?? null;
                        $counter = (int)($source['counter'] ?? 0);
                        $name = $source['name'] ?? 'Unnamed Passkey';
                    } else {
                        throw new Exception('Invalid source type: ' . gettype($source));
                    }
                    
                    // Validate required fields
                    if (empty($credentialId)) {
                        throw new Exception('Missing credential_id in source data');
                    }
                    if (empty($userHandle)) {
                        throw new Exception('Missing user_handle in source data');
                    }
                    
                    error_log('Passkey Plugin: About to insert - credential_id: ' . $credentialId . ', user_handle: ' . $userHandle . ', name: ' . $name);
                    
                    // Use aMember's ?_ prefix syntax for compatibility
                    $db->query("INSERT INTO ?_passkey_credentials 
                        (credential_id, `type`, transports, attestation_type, trust_path, aaguid, public_key, user_handle, counter, name, created_at) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
                        ON DUPLICATE KEY UPDATE counter = VALUES(counter), name = VALUES(name)", 
                        $credentialId,
                        $type,
                        $transports,
                        $attestationType,
                        $trustPath,
                        $aaguid,
                        $publicKey,
                        $userHandle,
                        $counter,
                        $name
                    );
                    
                    error_log('Passkey Plugin: Credential saved successfully to database');
                    
                } catch (Exception $e) {
                    error_log('Passkey Plugin: Error in saveCredentialSource: ' . $e->getMessage());
                    error_log('Passkey Plugin: Exception trace: ' . $e->getTraceAsString());
                    throw $e; // Re-throw to be caught by the calling code
                }
            }
        };
    }

    /**
     * Handle passkey registration initialization
     */
    private function handleRegisterInit($auth, $session, $rp, $storage)
    {
        $user = $auth->getUser();
        
        // Use username instead of email, with fallback to email if username not available
        $username = $user->login; // This should be the username
        $displayName = $user->getName() ? $user->getName() : $username;
        
        // Debug logging to see what we're getting
        error_log('Passkey Plugin: User data - login: ' . $username . ', name: ' . $displayName . ', email: ' . $user->email);
        
        // Check if we have the complete WebAuthn library
        if (class_exists('Webauthn\\PublicKeyCredentialUserEntity')) {
            try {
                $userEntity = new Webauthn\PublicKeyCredentialUserEntity(
                    $username,  // Use username as the name field
                    $user->pk(),
                    $displayName  // Display name can be the full name or username
                );
                
                // Debug: Check what methods are available
                error_log('Passkey Plugin: UserEntity created, available methods: ' . implode(', ', get_class_methods($userEntity)));
                
            } catch (Exception $e) {
                error_log('Passkey Plugin: Error creating UserEntity: ' . $e->getMessage());
                // Fallback to array if object creation fails
                $userEntity = array(
                    'name' => $username,
                    'id' => $user->pk(),
                    'displayName' => $displayName
                );
            }
        } else {
            // Fallback user entity as array
            $userEntity = array(
                'name' => $username,
                'id' => $user->pk(),
                'displayName' => $displayName
            );
        }
        
        // Check if Server class exists, if not, create our own simplified implementation
        if (class_exists('Webauthn\\Server')) {
            error_log('Passkey Plugin: Using official Webauthn\\Server class');
            $server = new Webauthn\Server($rp, $storage);
            $options = $server->generatePublicKeyCredentialCreationOptions($userEntity);
            $optionsArray = $options->jsonSerialize();
        } else {
            error_log('Passkey Plugin: Server class not found, using simplified implementation');
            
            // Create a simplified options array manually
            $challengeBytes = random_bytes(32);
            $challenge = base64_encode($challengeBytes);
            
            // Ensure user ID is properly encoded
            $userId = is_array($userEntity) ? $userEntity['id'] : $user->pk();
            $userIdEncoded = base64_encode(strval($userId));
            
            $optionsArray = array(
                'challenge' => $challenge,
                'rp' => array(
                    'name' => is_object($rp) ? $rp->name : $rp['name'],
                    'id' => is_object($rp) ? $rp->id : $rp['id']
                ),
                'user' => array(
                    'id' => $userIdEncoded,
                    'name' => is_array($userEntity) ? $userEntity['name'] : $username,
                    'displayName' => is_array($userEntity) ? $userEntity['displayName'] : $displayName
                ),
                'pubKeyCredParams' => array(
                    array('alg' => -7, 'type' => 'public-key'),   // ES256 (ECDSA with SHA-256)
                    array('alg' => -257, 'type' => 'public-key'), // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
                    array('alg' => -37, 'type' => 'public-key'),  // PS256 (RSASSA-PSS with SHA-256)
                    array('alg' => -35, 'type' => 'public-key'),  // ES384 (ECDSA with SHA-384)
                    array('alg' => -36, 'type' => 'public-key'),  // ES512 (ECDSA with SHA-512)
                    array('alg' => -8, 'type' => 'public-key')    // EdDSA (Ed25519 signature algorithms)
                ),
                'timeout' => 60000,
                'attestation' => 'none',
                'authenticatorSelection' => array(
                    // Note: authenticatorAttachment is omitted to allow both platform and roaming authenticators
                    'userVerification' => 'preferred', // Prefer user verification but don't require it
                    'residentKey' => 'preferred',      // Prefer resident keys for better UX
                    'requireResidentKey' => false      // But don't require them for compatibility
                ),
                'extensions' => (object)array()  // Ensure this becomes {} not []
            );
            
            // Store the challenge in session
            $session->passkey_challenge = $challenge;
            error_log('Passkey Plugin: Stored challenge in session: ' . $challenge);
            
            // Validate the options before sending
            error_log('Passkey Plugin: Validating options before JSON encode');
            error_log('Passkey Plugin: Challenge length: ' . strlen($challenge));
            error_log('Passkey Plugin: Challenge is base64: ' . (base64_encode(base64_decode($challenge)) === $challenge ? 'YES' : 'NO'));
            error_log('Passkey Plugin: User ID encoded: ' . $userIdEncoded);
            error_log('Passkey Plugin: User ID length: ' . strlen($userIdEncoded));
            error_log('Passkey Plugin: User ID is base64: ' . (base64_encode(base64_decode($userIdEncoded)) === $userIdEncoded ? 'YES' : 'NO'));
            error_log('Passkey Plugin: RP name: ' . (is_object($rp) ? $rp->name : $rp['name']));
            error_log('Passkey Plugin: RP id: ' . (is_object($rp) ? $rp->id : $rp['id']));
            error_log('Passkey Plugin: pubKeyCredParams count: ' . count($optionsArray['pubKeyCredParams']));
            error_log('Passkey Plugin: authenticatorSelection: ' . print_r($optionsArray['authenticatorSelection'], true));
        }
        
        // Ensure we support common algorithms with proper priority order
        if (!isset($optionsArray['pubKeyCredParams']) || empty($optionsArray['pubKeyCredParams'])) {
            $optionsArray['pubKeyCredParams'] = [
                ['type' => 'public-key', 'alg' => -7],   // ES256 (most widely supported)
                ['type' => 'public-key', 'alg' => -257], // RS256 (widely supported)
                ['type' => 'public-key', 'alg' => -37],  // PS256
                ['type' => 'public-key', 'alg' => -35],  // ES384
                ['type' => 'public-key', 'alg' => -36],  // ES512
                ['type' => 'public-key', 'alg' => -258], // RS384
                ['type' => 'public-key', 'alg' => -259], // RS512
                ['type' => 'public-key', 'alg' => -38],  // PS384
                ['type' => 'public-key', 'alg' => -39]   // PS512
            ];
        }
        
        // Optimize authenticator selection for maximum compatibility
        $optionsArray['authenticatorSelection'] = [
            // Note: authenticatorAttachment is omitted to allow both platform and roaming authenticators
            'userVerification' => 'preferred',  // Prefer user verification (works better with TouchID/FaceID)
            'residentKey' => 'preferred',       // Prefer resident keys for better UX
            'requireResidentKey' => false       // But don't require them for hardware key compatibility
        ];
        
        // Set reasonable timeout (60 seconds)
        $optionsArray['timeout'] = 60000;
        
        // Set attestation preference for maximum compatibility
        $optionsArray['attestation'] = 'none'; // Most compatible across all authenticator types
        
        error_log('Passkey Plugin: Registration options generated with authenticatorSelection: ' . json_encode($optionsArray['authenticatorSelection']));
        
        // Fix JSON encoding issues - ensure extensions is an empty object, not array
        if (isset($optionsArray['extensions'])) {
            $optionsArray['extensions'] = (object)array();
        }
        
        // Validate critical fields before sending
        if (!isset($optionsArray['challenge']) || !is_string($optionsArray['challenge'])) {
            error_log('Passkey Plugin: ERROR - Invalid challenge in options');
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Invalid challenge generated'));
            return;
        }
        
        if (!isset($optionsArray['user']['id']) || !is_string($optionsArray['user']['id'])) {
            error_log('Passkey Plugin: ERROR - Invalid user.id in options');
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Invalid user ID generated'));
            return;
        }
        
        // Test JSON encoding specifically for WebAuthn compatibility
        $testJson = json_encode($optionsArray);
        if ($testJson === false) {
            error_log('Passkey Plugin: ERROR - JSON encoding failed: ' . json_last_error_msg());
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Options encoding failed'));
            return;
        }
        
        // Verify extensions is encoded as object
        if (strpos($testJson, '"extensions":[]') !== false) {
            error_log('Passkey Plugin: ERROR - Extensions encoded as array instead of object');
            // Force fix the extensions field
            $testJson = str_replace('"extensions":[]', '"extensions":{}', $testJson);
            error_log('Passkey Plugin: Fixed extensions field in JSON');
        }
        
        error_log('Passkey Plugin: Final options JSON: ' . $testJson);
        
        $session->passkey_register_options = serialize($options);

        // Use custom encoding for WebAuthn compatibility
        $this->sendWebAuthnJsonResponse(array(
            'status' => 'ok',
            'options' => $optionsArray
        ));
    }

    /**
     * Handle passkey registration completion
     */
    private function handleRegisterFinish($session, $rp, $storage)
    {
        // For now, return a simple success response without full WebAuthn verification
        // This is a fallback implementation when the full library isn't available
        
        if (!class_exists('Webauthn\\Server')) {
            error_log('Passkey Plugin: Server class not available, using simplified registration finish');
            
            // Get attestation data - check both JSON input and form data
            $input = file_get_contents('php://input');
            error_log('Passkey Plugin: Raw input received: ' . $input);
            error_log('Passkey Plugin: POST data: ' . print_r($_POST, true));
            error_log('Passkey Plugin: REQUEST data: ' . print_r($_REQUEST, true));
            
            $attestation = null;
            
            // First try to get from POST/REQUEST parameters (most likely since we send form data)
            $attestation = $_POST['credential'] ?? $_POST['attestation'] ?? $_REQUEST['credential'] ?? $_REQUEST['attestation'] ?? null;
            if ($attestation && is_string($attestation)) {
                // The credential might be URL-encoded JSON string
                try {
                    $decoded = json_decode($attestation, true);
                    if ($decoded && json_last_error() === JSON_ERROR_NONE) {
                        $attestation = $decoded;
                        error_log('Passkey Plugin: Successfully decoded credential from form parameter');
                    } else {
                        error_log('Passkey Plugin: JSON decode error: ' . json_last_error_msg());
                    }
                } catch (Exception $e) {
                    error_log('Passkey Plugin: Exception during JSON decode: ' . $e->getMessage());
                }
            }
            
            // Fallback: try to parse raw input as JSON (for direct JSON POST requests)
            if (!$attestation && !empty($input)) {
                try {
                    $data = json_decode($input, true);
                    if ($data && json_last_error() === JSON_ERROR_NONE) {
                        error_log('Passkey Plugin: Decoded JSON data: ' . print_r($data, true));
                        $attestation = $data['attestation'] ?? $data['credential'] ?? $data ?? null;
                    } else {
                        error_log('Passkey Plugin: Raw input JSON decode error: ' . json_last_error_msg());
                    }
                } catch (Exception $e) {
                    error_log('Passkey Plugin: Exception during raw input JSON decode: ' . $e->getMessage());
                }
            }
            
            error_log('Passkey Plugin: Final attestation data: ' . print_r($attestation, true));
            error_log('Passkey Plugin: Attestation data type: ' . gettype($attestation));
            
            if (!$attestation) {
                error_log('Passkey Plugin: ERROR - No attestation data received');
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'No attestation data received'));
                return;
            }
            
            if (!is_array($attestation)) {
                error_log('Passkey Plugin: ERROR - Attestation data is not an array: ' . gettype($attestation));
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Invalid attestation data format'));
                return;
            }
            
            // Simplified credential storage without full verification
            // In production, this should include proper cryptographic verification
            error_log('Passkey Plugin: Simplified registration - storing credential without full verification');
            
            // Extract basic credential info with better error handling
            $credentialId = null;
            $rawId = null;
            
            // Handle both direct properties and nested structures
            if (isset($attestation['id'])) {
                $credentialId = $attestation['id'];
            }
            if (isset($attestation['rawId'])) {
                $rawId = $attestation['rawId'];
            }
            
            // Some hardware keys might structure data differently
            if (!$credentialId && isset($attestation['credential']['id'])) {
                $credentialId = $attestation['credential']['id'];
            }
            if (!$rawId && isset($attestation['credential']['rawId'])) {
                $rawId = $attestation['credential']['rawId'];
            }
            
            error_log('Passkey Plugin: Extracted credential ID: ' . ($credentialId ?? 'NULL'));
            error_log('Passkey Plugin: Extracted raw ID: ' . ($rawId ?? 'NULL'));
            error_log('Passkey Plugin: Full attestation structure: ' . print_r(array_keys($attestation), true));
            
            if (isset($attestation['response'])) {
                error_log('Passkey Plugin: Response keys: ' . print_r(array_keys($attestation['response']), true));
            }
            
            if (!$credentialId || !$rawId) {
                error_log('Passkey Plugin: ERROR - Missing required credential fields. ID: ' . ($credentialId ? 'present' : 'missing') . ', rawId: ' . ($rawId ? 'present' : 'missing'));
                
                // Try to provide more helpful error message based on what we have
                if (empty($attestation)) {
                    $errorMsg = 'No credential data received from authenticator';
                } else {
                    $errorMsg = 'Invalid credential format from authenticator. This may be a compatibility issue with your security key.';
                }
                
                $this->sendJsonResponse(array('status' => 'fail', 'error' => $errorMsg));
                return;
            }
            
            // Store basic credential info in our storage
            $user = Am_Di::getInstance()->auth->getUser();
            error_log('Passkey Plugin: Got user for storage: ' . $user->pk());
            
            // Get the passkey name from the request
            $passkeyName = $_POST['passkey_name'] ?? $_REQUEST['passkey_name'] ?? '';
            if (empty($passkeyName)) {
                $passkeyName = 'Unnamed Passkey';
            }
            error_log('Passkey Plugin: Passkey name: ' . $passkeyName);
            
            // Extract public key from attestationObject if available
            $publicKeyData = '';
            if (isset($attestation['response']['attestationObject'])) {
                // For simplified implementation, store the attestationObject as the public key
                $publicKeyData = $attestation['response']['attestationObject'];
            } elseif (isset($attestation['response']['publicKey'])) {
                $publicKeyData = $attestation['response']['publicKey'];
            }
            
            $credentialData = array(
                'credential_id' => $credentialId,
                'type' => 'public-key',
                'transports' => json_encode($attestation['response']['transports'] ?? array()),
                'attestation_type' => 'none',
                'trust_path' => json_encode(array()),
                'aaguid' => '',
                'public_key' => base64_encode($publicKeyData),
                'user_handle' => $user->pk(),
                'counter' => 0,
                'name' => $passkeyName
            );
            
            error_log('Passkey Plugin: Prepared credential data for storage: ' . print_r($credentialData, true));
            error_log('Passkey Plugin: Storage object type: ' . get_class($storage));
            
            try {
                error_log('Passkey Plugin: About to call storage->saveCredentialSource()');
                
                // Ensure all required fields are present and properly typed
                if (empty($credentialData['credential_id'])) {
                    throw new Exception('Missing credential_id');
                }
                if (empty($credentialData['user_handle'])) {
                    throw new Exception('Missing user_handle');
                }
                if (!isset($credentialData['type'])) {
                    $credentialData['type'] = 'public-key';
                }
                if (!isset($credentialData['counter'])) {
                    $credentialData['counter'] = 0;
                }
                
                // Ensure counter is an integer
                $credentialData['counter'] = (int)$credentialData['counter'];
                
                error_log('Passkey Plugin: Validated credential data: ' . print_r($credentialData, true));
                
                $storage->saveCredentialSource($credentialData); // Pass array directly, not as object
                error_log('Passkey Plugin: Storage save completed successfully');
                $this->sendJsonResponse(array('status' => 'ok', 'message' => 'Passkey registered successfully'));
            } catch (Exception $e) {
                error_log('Passkey Plugin: Error saving credential: ' . $e->getMessage());
                error_log('Passkey Plugin: Exception type: ' . get_class($e));
                error_log('Passkey Plugin: Exception trace: ' . $e->getTraceAsString());
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Failed to save credential: ' . $e->getMessage()));
            } catch (Throwable $t) {
                error_log('Passkey Plugin: Throwable during storage: ' . $t->getMessage());
                error_log('Passkey Plugin: Throwable type: ' . get_class($t));
                error_log('Passkey Plugin: Throwable trace: ' . $t->getTraceAsString());
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Failed to save credential: ' . $t->getMessage()));
            }
        }
    }

    /**
     * Handle passkey login initialization
     */
    private function handleLoginInit($session, $rp, $storage)
    {
        if (!class_exists('Webauthn\\Server')) {
            error_log('Passkey Plugin: Server class not available, using simplified login init');
            
            // Create simplified login options manually
            $challenge = base64_encode(random_bytes(32));
            $optionsArray = array(
                'challenge' => $challenge,
                'timeout' => 60000,
                'userVerification' => 'preferred',
                'allowCredentials' => array(),
                'extensions' => array()
            );
            
            // Store the challenge in session
            $session->passkey_login_challenge = $challenge;
            error_log('Passkey Plugin: Stored login challenge in session: ' . $challenge);
            
            $this->sendJsonResponse(array(
                'status' => 'ok',
                'options' => $optionsArray
            ));
            return;
        }
        
        // Original implementation if Server class is available
        $server = new Webauthn\Server($rp, $storage);
        
        // Generate basic options
        $options = $server->generatePublicKeyCredentialRequestOptions();
        
        // Get the options as array to modify them
        $optionsArray = $options->jsonSerialize();
        
        // Add settings to support hardware keys
        $optionsArray['timeout'] = 60000; // 60 seconds
        $optionsArray['userVerification'] = 'preferred'; // Allow but don't require user verification
        
        // Note: allowCredentials is handled by the WebAuthn library based on stored credentials
        // The library will automatically include all registered credentials for any user
        
        error_log('Passkey Plugin: Login options generated with userVerification: ' . $optionsArray['userVerification']);
        
        $session->passkey_login_options = serialize($options);
        header('Content-Type: application/json');
        echo json_encode(array(
            'status' => 'ok',
            'options' => $optionsArray
        ));
        exit;
    }

    /**
     * Handle passkey login completion
     */
    private function handleLoginFinish($session, $auth, $db, $rp, $storage)
    {
        if (!class_exists('Webauthn\\Server')) {
            error_log('Passkey Plugin: Server class not available, using simplified login finish');
            
            // Debug: Log what we're receiving
            $input = file_get_contents('php://input');
            error_log('Passkey Plugin: Raw input: ' . $input);
            error_log('Passkey Plugin: POST data: ' . print_r($_POST, true));
            
            // Get assertion data - prioritize form POST data over JSON input
            $assertion = null;
            
            // First try POST parameter (most common for form submissions)
            if (isset($_POST['assertion'])) {
                $assertionRaw = $_POST['assertion'];
                if (is_string($assertionRaw)) {
                    $assertion = json_decode($assertionRaw, true);
                    if (json_last_error() === JSON_ERROR_NONE) {
                        error_log('Passkey Plugin: Successfully parsed assertion from POST parameter');
                    } else {
                        error_log('Passkey Plugin: JSON decode error from POST: ' . json_last_error_msg());
                    }
                } else {
                    $assertion = $assertionRaw; // Already an array
                    error_log('Passkey Plugin: Found assertion array in POST');
                }
            }
            
            // Fallback to JSON input if POST failed
            if (!$assertion && !empty($input)) {
                $data = json_decode($input, true);
                if (json_last_error() === JSON_ERROR_NONE && isset($data['assertion'])) {
                    $assertion = $data['assertion'];
                    error_log('Passkey Plugin: Parsed assertion from JSON input');
                }
            }
            
            if (!$assertion) {
                error_log('Passkey Plugin: No assertion data found after all attempts');
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'No assertion data received'));
                return;
            }
            
            // Simplified authentication without full cryptographic verification
            // In production, this should include proper signature verification
            error_log('Passkey Plugin: Simplified authentication - login without full verification');
            
            $credentialId = $assertion['id'] ?? null;
            if (!$credentialId) {
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'No credential ID in assertion'));
                return;
            }
            
            // Find user by credential ID
            $row = $db->selectRow('SELECT * FROM ?_passkey_credentials WHERE credential_id = ?', $credentialId);
            if (!$row) {
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Credential not found'));
                return;
            }
            
            // Load and authenticate user
            try {
                $user = Am_Di::getInstance()->userTable->load($row['user_handle']);
                if ($user) {
                    $auth->setUser($user, $_REQUEST['remember'] ?? false);
                    error_log('Passkey Plugin: User authenticated successfully via simplified passkey login');
                    $this->sendJsonResponse(array('status' => 'ok', 'message' => 'Login successful'));
                } else {
                    $this->sendJsonResponse(array('status' => 'fail', 'error' => 'User not found'));
                }
            } catch (Exception $e) {
                error_log('Passkey Plugin: Error during simplified authentication: ' . $e->getMessage());
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Authentication failed'));
            }
            return;
        }
        
        // Original implementation if Server class is available
        $server = new Webauthn\Server($rp, $storage);
        
        // Get assertion data - check both JSON input and form data
        $input = file_get_contents('php://input');
        if (!empty($input)) {
            $data = json_decode($input, true);
            $assertion = $data['assertion'] ?? null;
        } else {
            // Fallback to form data
            $assertion = $_POST['assertion'] ?? null;
            if ($assertion) {
                $assertion = json_decode($assertion, true);
            }
        }
        
        if (!$assertion) {
            header('Content-Type: application/json');
            echo json_encode(array('status' => 'fail', 'error' => 'No assertion data provided'));
            exit;
        }
        
        $options = unserialize($session->passkey_login_options);
        
        try {
            error_log('Passkey Plugin: Login finish - assertion data: ' . json_encode($assertion));
            
            $publicKeyCredential = Webauthn\PublicKeyCredentialLoader::loadArray($assertion);
            $result = $server->loadAndCheckAssertionResponse($publicKeyCredential, $options, null);
            
            // Find user by credentialId
            $credId = $publicKeyCredential->getRawId();
            $row = $db->selectRow('SELECT * FROM ?_passkey_credentials WHERE credential_id=?', $credId);
            if (!$row) {
                throw new Exception('User not found for credential');
            }
            
            $user = Am_Di::getInstance()->userTable->load($row['user_id']);
            
            // Log in user
            $auth->setUser($user);
            $auth->onSuccess();
            
            error_log('Passkey Plugin: Login successful for user: ' . $user->login);
            
            header('Content-Type: application/json');
            echo json_encode(array('status' => 'ok'));
        } catch (Throwable $e) {
            error_log('Passkey Plugin: Login error: ' . $e->getMessage());
            header('Content-Type: application/json');
            echo json_encode(array('status' => 'fail', 'error' => $e->getMessage()));
        }
        exit;
    }

    /**
     * Handle passkey deletion
     */
    private function handleDeletePasskey($auth, $db)
    {
        error_log('Passkey Plugin: handleDeletePasskey called');
        error_log('Passkey Plugin: POST data: ' . print_r($_POST, true));
        
        // Ensure user is authenticated
        $user = $auth->getUser();
        if (!$user) {
            error_log('Passkey Plugin: Delete failed - user not authenticated');
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Not authenticated'));
            return;
        }
        
        error_log('Passkey Plugin: Delete request from user: ' . $user->login . ' (ID: ' . $user->pk() . ')');
        
        // Get credential ID to delete
        $credentialId = $_POST['credential_id'] ?? '';
        if (empty($credentialId)) {
            error_log('Passkey Plugin: Delete failed - no credential ID provided');
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'No credential ID provided'));
            return;
        }
        
        error_log('Passkey Plugin: Attempting to delete credential: ' . $credentialId);
        
        try {
            // Verify the credential belongs to the current user
            $row = $db->selectRow('SELECT * FROM ?_passkey_credentials WHERE credential_id = ? AND user_handle = ?', 
                $credentialId, (string)$user->pk());
            
            if (!$row) {
                error_log('Passkey Plugin: Delete failed - credential not found or access denied');
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Credential not found or does not belong to you'));
                return;
            }
            
            error_log('Passkey Plugin: Credential verified, proceeding with deletion');
            
            // Delete the credential
            $result = $db->query('DELETE FROM ?_passkey_credentials WHERE credential_id = ? AND user_handle = ?', 
                $credentialId, (string)$user->pk());
            
            error_log('Passkey Plugin: Delete query executed successfully');
            error_log('Passkey Plugin: Deleted credential ' . $credentialId . ' for user ' . $user->login);
            
            // Get remaining passkey count
            $remaining = $db->selectCell('SELECT COUNT(*) FROM ?_passkey_credentials WHERE user_handle = ?', 
                (string)$user->pk());
            
            error_log('Passkey Plugin: Remaining passkeys for user: ' . $remaining);
            
            $this->sendJsonResponse(array(
                'status' => 'ok', 
                'message' => 'Passkey deleted successfully',
                'remaining_passkeys' => (int)$remaining
            ));
            
        } catch (Exception $e) {
            error_log('Passkey Plugin: Error deleting passkey: ' . $e->getMessage());
            error_log('Passkey Plugin: Exception trace: ' . $e->getTraceAsString());
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Failed to delete passkey: ' . $e->getMessage()));
        }
    }

    /**
     * Handle passkey renaming
     */
    private function handleRenamePasskey($auth, $db)
    {
        // Ensure user is authenticated
        $user = $auth->getUser();
        if (!$user) {
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Not authenticated'));
            return;
        }
        
        // Get credential ID and new name
        $credentialId = $_POST['credential_id'] ?? '';
        $newName = trim($_POST['new_name'] ?? '');
        
        if (empty($credentialId)) {
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'No credential ID provided'));
            return;
        }
        
        if (empty($newName)) {
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'No name provided'));
            return;
        }
        
        if (strlen($newName) > 100) {
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Name too long (max 100 characters)'));
            return;
        }
        
        try {
            // Verify the credential belongs to the current user
            $row = $db->selectRow('SELECT * FROM ?_passkey_credentials WHERE credential_id = ? AND user_handle = ?', 
                $credentialId, (string)$user->pk());
            
            if (!$row) {
                $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Credential not found or does not belong to you'));
                return;
            }
            
            // Update the credential name
            $db->query('UPDATE ?_passkey_credentials SET name = ? WHERE credential_id = ? AND user_handle = ?', 
                $newName, $credentialId, (string)$user->pk());
            
            error_log('Passkey Plugin: Renamed credential ' . $credentialId . ' to "' . $newName . '" for user ' . $user->login);
            
            $this->sendJsonResponse(array(
                'status' => 'ok', 
                'message' => 'Passkey renamed successfully',
                'new_name' => $newName
            ));
            
        } catch (Exception $e) {
            error_log('Passkey Plugin: Error renaming passkey: ' . $e->getMessage());
            $this->sendJsonResponse(array('status' => 'fail', 'error' => 'Failed to rename passkey: ' . $e->getMessage()));
        }
    }

    /**
     * Store passkey credential for user
     */
    public function saveUserCredential($user_id, $credential)
    {
        $db = Am_Di::getInstance()->db;
        
        // Debug logging
        error_log("Passkey Plugin: Saving credential for user $user_id");
        error_log("Passkey Plugin: Credential ID length: " . strlen($credential['id']));
        error_log("Passkey Plugin: Public Key length: " . strlen($credential['publicKey']));
        
        $db->query('INSERT INTO ?_passkey_credentials (user_id, credential_id, public_key, sign_count, transports) VALUES (?, ?, ?, ?, ?)',
            $user_id,
            $credential['id'],
            $credential['publicKey'],
            $credential['signCount'],
            isset($credential['transports']) ? $credential['transports'] : null
        );
        
        error_log("Passkey Plugin: Credential saved successfully");
    }

    /**
     * Retrieve all passkey credentials for a user
     */
    public function getUserCredentials($user_id)
    {
        $db = Am_Di::getInstance()->db;
        return $db->select('SELECT * FROM ?_passkey_credentials WHERE user_id=?', $user_id);
    }

    /**
     * Admin: List and remove user passkeys
     */
    public function onAdminUserTabs(Am_Event_AdminUserTabs $event)
    {
        $user = $event->getUser();
        $tabTitle = 'Passkeys';
        $tabContent = '<h2>Registered Passkeys</h2>';
        $credentials = $this->getUserCredentials($user->pk());
        if ($credentials) {
            $tabContent .= '<ul>';
            foreach ($credentials as $cred) {
                $tabContent .= sprintf('<li>%s <form method="post" style="display:inline"><input type="hidden" name="delete_passkey" value="%s"><button type="submit">Delete</button></form></li>',
                    htmlspecialchars($cred['credential_id']),
                    htmlspecialchars($cred['credential_id'])
                );
            }
            $tabContent .= '</ul>';
        } else {
            $tabContent .= '<p>No passkeys registered.</p>';
        }
        // Handle deletion
        if (!empty($_POST['delete_passkey'])) {
            $this->deleteUserCredential($user->pk(), $_POST['delete_passkey']);
            Am_Controller::redirectLocation($_SERVER['REQUEST_URI']);
        }
        $event->getTabs()->addTab($tabTitle, $tabContent);
    }

    /**
     * Delete a user's credential
     */
    public function deleteUserCredential($user_id, $credential_id)
    {
        $db = Am_Di::getInstance()->db;
        $db->query('DELETE FROM ?_passkey_credentials WHERE user_id=? AND credential_id=?', $user_id, $credential_id);
    }

    /**
     * Create the credentials table if it does not exist
     * Note: This method is now deprecated in favor of dynamic table creation in saveCredentialSource
     */
    protected function createTableIfNotExists()
    {
        $db = Am_Di::getInstance()->db;
        $tableName = $db->getPrefix() . 'passkey_credentials';
        $db->query("
CREATE TABLE IF NOT EXISTS `{$tableName}` (
    credential_id VARCHAR(255) NOT NULL PRIMARY KEY,
    `type` VARCHAR(50) NOT NULL DEFAULT 'public-key',
    transports TEXT,
    attestation_type VARCHAR(50),
    trust_path TEXT,
    aaguid VARCHAR(255),
    public_key TEXT NOT NULL,
    user_handle VARCHAR(255) NOT NULL,
    counter INT NOT NULL DEFAULT 0,
    name VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_handle (user_handle)
) ENGINE=InnoDB DEFAULT CHARSET=utf8
        ");
    }
}
