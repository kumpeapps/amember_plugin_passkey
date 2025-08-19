<?php

/**
 * Plugin Name: Passkey Login (FIDO2/WebAuthn)
 * Description: Enable Passkey (FIDO2/WebAuthn) login for members and admins.
 * Author: Copilot
 * @am_plugin_group misc
 * @am_plugin_api 6.0
 */

class Am_Plugin_Passkey extends Am_Plugin
{
    /**
     * Register config form using onSetupForms (Facebook plugin pattern)
     */
    public function onSetupForms(Am_Event_SetupForms $event)
    {
        $form = new Am_Form_Setup('passkey');
        $form->setTitle('Passkey Login');
        $form->addHtml('<!-- Passkey plugin: config form marker -->');
        $form->addAdvCheckbox('enable_passkey')->setLabel('Enable Passkey Login');
        $form->addText('rp_name', ['class' => 'am-el-wide'])->setLabel('Relying Party Name')->setValue('aMember');
        $form->addText('rp_id', ['class' => 'am-el-wide'])->setLabel('Relying Party ID')->setValue($_SERVER['HTTP_HOST']);
        $event->addForm($form);
    }

    /**
     * Add Passkey login block to login form using aMember blocks system
     */
    public function onInitFinished(Am_Event $event)
    {
        $this->getDi()->blocks->add(
            'login/form/before',
            new Am_Block_Base(
                'passkey-block:passkey-login.phtml',
                'passkey-login',
                $this,
                null,
                'Passkey Login',
                100
            )
        );
    }
    protected $id = 'passkey';
    protected $title = 'Passkey Login';
    protected $description = 'Enable Passkey (FIDO2/WebAuthn) login for members and admins.';
    protected $table = 'passkey_credentials';

    public function __construct($config, $id)
    {
        parent::__construct($config, $id);
        Am_Di::getInstance()->hook->add('aJAX', [$this, 'onAjax']);
        Am_Di::getInstance()->hook->add('userProfile', [$this, 'onUserProfile']);
        Am_Di::getInstance()->hook->add('adminUserTabs', [$this, 'onAdminUserTabs']);
        Am_Di::getInstance()->hook->add('authGetLoginForm', [$this, 'onAuthGetLoginForm']);
        $this->createTableIfNotExists();
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
     * Hook into user profile to allow registration of a passkey (FIDO2/WebAuthn credential)
     */
    public function onUserProfile(Am_Event_UserProfile $event)
    {
        $config = Am_Di::getInstance()->config;
        if (!$config->get('passkey.enable_passkey')) return;
        $user = $event->getUser();
        $form = $event->getForm();
        // Only show registration UI if the current user is editing their own profile
        $currentUser = null;
        if (method_exists(Am_Di::getInstance()->auth, 'getUser')) {
            $currentUser = Am_Di::getInstance()->auth->getUser();
        }
        if ($currentUser && $currentUser->pk() == $user->pk()) {
            $form->addHtml('<!-- Passkey plugin: onUserProfile marker --><div id="passkey-register">
                <button type="button" id="btn-passkey-register">Register Passkey</button>
                <div id="passkey-register-status"></div>
            </div>');
            $form->addScript(<<<JS
document.getElementById('btn-passkey-register').onclick = async function() {
    let resp = await fetch("/amember/ajax/passkey-register-init", {method: "POST", credentials: "same-origin"});
    let data = await resp.json();
    if (!data.options) return alert('Failed to get registration options');
    let publicKey = data.options;
    publicKey.challenge = Uint8Array.from(atob(publicKey.challenge), c => c.charCodeAt(0));
    publicKey.user.id = Uint8Array.from(atob(publicKey.user.id), c => c.charCodeAt(0));
    let cred;
    try {
        cred = await navigator.credentials.create({publicKey});
    } catch (e) {
        document.getElementById('passkey-register-status').innerText = 'Registration failed: ' + e;
        return;
    }
    let attestation = {
        id: cred.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(cred.rawId))),
        type: cred.type,
        response: {
            clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON))),
            attestationObject: btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject)))
        }
    };
    let finish = await fetch("/amember/ajax/passkey-register-finish", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        credentials: "same-origin",
        body: JSON.stringify({attestation})
    });
    let finishData = await finish.json();
    if (finishData.status === 'ok') {
        document.getElementById('passkey-register-status').innerText = 'Passkey registered!';
    } else {
        document.getElementById('passkey-register-status').innerText = 'Registration failed: ' + (finishData.error || 'Unknown error');
    }
};
JS
            );
        }
    }

    /**
     * Hook into login form to allow passkey login
     */
    public function onAuthGetLoginForm(Am_Event_AuthGetLoginForm $event)
    {
        $config = Am_Di::getInstance()->config;
        if (!$config->get('passkey.enable_passkey')) return;
        $form = $event->getForm();
        // Add debug marker
        $form->addHtml('<div style="color:blue;font-weight:bold;">[Passkey Plugin Debug: onAuthGetLoginForm called]</div>');
        // Also register the block here for redundancy
        Am_Di::getInstance()->blocks->add(
            'login/form/before',
            new Am_Block_Base(
                'passkey-block:passkey-login.phtml',
                'passkey-login',
                $this,
                null,
                'Passkey Login',
                100
            )
        );
    }

    /**
     * Authenticate user using passkey (FIDO2/WebAuthn)
     */
    public function onAuthenticate(Am_Event_Authenticate $event)
    {
        // This method is not used for passkey login, as authentication is handled via AJAX and session.
    }

    /**
     * AJAX handler for registration and login
     */
    public function onAjax(Am_Event $event)
    {
        // Composer autoload only required here to avoid session conflicts
        $autoload = __DIR__ . '/../../../../../vendor/autoload.php';
        if (!file_exists($autoload)) {
            error_log('Passkey plugin error: vendor/autoload.php not found. Run composer install.');
            if (php_sapi_name() !== 'cli') {
                echo '<b>Passkey plugin error:</b> vendor/autoload.php not found. Run <code>composer install</code> in your project root.';
                exit;
            }
        }
        require_once $autoload;
        $action = $_REQUEST['action'] ?? '';
        $session = Am_Di::getInstance()->session;
        $auth = Am_Di::getInstance()->auth;
        $db = Am_Di::getInstance()->db;
        $config = Am_Di::getInstance()->config;
        $rpName = $config->get('passkey.rp_name', 'aMember');
        $rpId = $config->get('passkey.rp_id', $_SERVER['HTTP_HOST']);
        $rp = new \Webauthn\RelyingParty($rpName, $rpId);
        $storage = new class($this) implements \Webauthn\PublicKeyCredentialSourceRepository {
            private $plugin;
            public function __construct($plugin) { $this->plugin = $plugin; }
            public function findOneByCredentialId($credentialId) {
                $db = \Am_Di::getInstance()->db;
                $row = $db->selectRow('SELECT * FROM ?_passkey_credentials WHERE credential_id=?', $credentialId);
                if (!$row) return null;
                return new \Webauthn\PublicKeyCredentialSource(
                    $row['credential_id'],
                    $row['type'] ?? 'public-key',
                    $row['transports'] ? explode(',', $row['transports']) : [],
                    $row['user_id'],
                    $row['public_key'],
                    $row['sign_count'],
                    null
                );
            }
            public function findAllForUserEntity(\Webauthn\PublicKeyCredentialUserEntity $userEntity) {
                $db = \Am_Di::getInstance()->db;
                $rows = $db->select('SELECT * FROM ?_passkey_credentials WHERE user_id=?', $userEntity->getId());
                $result = [];
                foreach ($rows as $row) {
                    $result[] = new \Webauthn\PublicKeyCredentialSource(
                        $row['credential_id'],
                        $row['type'] ?? 'public-key',
                        $row['transports'] ? explode(',', $row['transports']) : [],
                        $row['user_id'],
                        $row['public_key'],
                        $row['sign_count'],
                        null
                    );
                }
                return $result;
            }
            public function saveCredentialSource(\Webauthn\PublicKeyCredentialSource $source) {
                $this->plugin->saveUserCredential($source->getUserHandle(), [
                    'id' => $source->getPublicKeyCredentialId(),
                    'publicKey' => $source->getCredentialPublicKey(),
                    'signCount' => $source->getCounter(),
                    'transports' => implode(',', $source->getTransports() ?? [])
                ]);
            }
        };

        // CSRF/session check for all AJAX actions
        if (!Am_Di::getInstance()->auth->getUser() && !in_array($action, ['passkey-login-init', 'passkey-login-finish'])) {
            header('Content-Type: application/json');
            echo json_encode(['status' => 'fail', 'error' => 'Not authenticated.']);
            exit;
        }

        if ($action === 'passkey-register-init') {
            $user = $auth->getUser();
            $userEntity = new \Webauthn\PublicKeyCredentialUserEntity(
                $user->login,
                $user->pk(),
                $user->getName() ?: $user->login
            );
            $server = new \Webauthn\Server($rp, $storage);
            $options = $server->generatePublicKeyCredentialCreationOptions($userEntity);
            $session->passkey_register_options = serialize($options);
            header('Content-Type: application/json');
            echo json_encode([
                'status' => 'ok',
                'options' => $options->jsonSerialize()
            ]);
            exit;
        }
        if ($action === 'passkey-register-finish') {
            $server = new \Webauthn\Server($rp, $storage);
            $data = json_decode(file_get_contents('php://input'), true);
            $options = unserialize($session->passkey_register_options);
            $attestation = $data['attestation'];
            try {
                $publicKeyCredential = \Webauthn\PublicKeyCredentialLoader::loadArray($attestation);
                $server->loadAndCheckAttestationResponse($publicKeyCredential, $options, null);
                header('Content-Type: application/json');
                echo json_encode(['status' => 'ok']);
            } catch (\Throwable $e) {
                header('Content-Type: application/json');
                echo json_encode(['status' => 'fail', 'error' => $e->getMessage()]);
            }
            exit;
        }
        if ($action === 'passkey-login-init') {
            $server = new \Webauthn\Server($rp, $storage);
            $options = $server->generatePublicKeyCredentialRequestOptions();
            $session->passkey_login_options = serialize($options);
            header('Content-Type: application/json');
            echo json_encode([
                'status' => 'ok',
                'options' => $options->jsonSerialize()
            ]);
            exit;
        }
        if ($action === 'passkey-login-finish') {
            $server = new \Webauthn\Server($rp, $storage);
            $data = json_decode(file_get_contents('php://input'), true);
            $options = unserialize($session->passkey_login_options);
            $assertion = $data['assertion'];
            try {
                $publicKeyCredential = \Webauthn\PublicKeyCredentialLoader::loadArray($assertion);
                $result = $server->loadAndCheckAssertionResponse($publicKeyCredential, $options, null);
                // Find user by credentialId
                $credId = $publicKeyCredential->getRawId();
                $row = $db->selectRow('SELECT * FROM ?_passkey_credentials WHERE credential_id=?', $credId);
                if (!$row) throw new \Exception('User not found for credential');
                $user = Am_Di::getInstance()->userTable->load($row['user_id']);
                // Log in user
                $auth->setUser($user);
                $auth->onSuccess();
                header('Content-Type: application/json');
                echo json_encode(['status' => 'ok']);
            } catch (\Throwable $e) {
                header('Content-Type: application/json');
                echo json_encode(['status' => 'fail', 'error' => $e->getMessage()]);
            }
            exit;
        }
    }

    /**
     * Store passkey credential for user
     */
    public function saveUserCredential($user_id, $credential)
    {
        $db = Am_Di::getInstance()->db;
        $db->query('INSERT INTO ?_passkey_credentials (user_id, credential_id, public_key, sign_count, transports) VALUES (?, ?, ?, ?, ?)',
            $user_id,
            $credential['id'],
            $credential['publicKey'],
            $credential['signCount'],
            isset($credential['transports']) ? $credential['transports'] : null
        );
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
     */
    protected function createTableIfNotExists()
    {
        $db = Am_Di::getInstance()->db;
        $db->query(<<<SQL
CREATE TABLE IF NOT EXISTS ?_passkey_credentials (
    user_id INT NOT NULL,
    credential_id VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INT NOT NULL,
    transports VARCHAR(255),
    PRIMARY KEY (user_id, credential_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
SQL
        );
    }
}
