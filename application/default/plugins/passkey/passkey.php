    // Enqueue JS on profile and login pages
    public function onAfterRender(Am_Event_AfterRender $event)
    {
        $view = $event->getView();
        $url = '/application/default/plugins/passkey/passkey.js';
        $view->headScript()->appendFile($url);
    }
    // AJAX endpoint for passkey registration (begin)
    public function onAuthControllerAction(Am_Event_AuthControllerAction $event)
    {
        $controller = $event->getController();
        $action = $controller->getParam('action');
        if ($action === 'passkey-begin-registration') {
            $user = $this->getDi()->auth->getUser();
            require_once __DIR__ . '/webauthn_helper.php';
            $result = beginRegistration([
                'id' => $user->pk,
                'name' => $user->login,
                'displayName' => $user->getName()
            ]);
            $controller->ajaxResponse($result);
            exit;
        }
        if ($action === 'passkey-finish-registration') {
            $user = $this->getDi()->auth->getUser();
            require_once __DIR__ . '/webauthn_helper.php';
            $clientData = $controller->getRequest()->getPost('clientData');
            $result = finishRegistration([
                'id' => $user->pk,
                'name' => $user->login,
                'displayName' => $user->getName()
            ], $clientData);
            $controller->ajaxResponse(['success' => $result]);
            exit;
        }
        if ($action === 'passkey-begin-authentication') {
            $login = $controller->getRequest()->getPost('login');
            $user = $this->getDi()->userTable->findFirstByLogin($login);
            require_once __DIR__ . '/webauthn_helper.php';
            $result = beginAuthentication([
                'id' => $user->pk,
                'name' => $user->login,
                'displayName' => $user->getName()
            ]);
            $controller->ajaxResponse($result);
            exit;
        }
        if ($action === 'passkey-finish-authentication') {
            $login = $controller->getRequest()->getPost('login');
            $user = $this->getDi()->userTable->findFirstByLogin($login);
            require_once __DIR__ . '/webauthn_helper.php';
            $clientData = $controller->getRequest()->getPost('clientData');
            $result = finishAuthentication([
                'id' => $user->pk,
                'name' => $user->login,
                'displayName' => $user->getName()
            ], $clientData);
            $controller->ajaxResponse(['success' => $result]);
            exit;
        }
    }
<?php
/**
 * Plugin Name: Passkey Login
 * Description: Adds Passkey (FIDO2/WebAuthn) login support to aMember for both admin and member logins.
 * Author: Your Name
 * Version: 0.1.0
 */

class Am_Plugin_Passkey extends Am_Plugin
{
    protected $id = 'passkey';
    protected $title = 'Passkey Login';
    protected $description = 'Enable Passkey (FIDO2/WebAuthn) login for members and admins.';

    public function _initSetupForm(Am_Form_Setup $form)
    {
        $form->addAdvCheckbox('enable_passkey')
            ->setLabel('Enable Passkey Login');
        $form->addText('rp_name', ['class' => 'am-el-wide'])
            ->setLabel('Relying Party Name (shown to users)')
            ->setValue('aMember');
        $form->addText('rp_id', ['class' => 'am-el-wide'])
            ->setLabel('Relying Party ID (domain)')
            ->setValue($_SERVER['HTTP_HOST']);
    }

    // Add passkey management tab to user profile
    public function onUserProfileTabs(Am_Event_UserProfileTabs $event)
    {
        $event->getTabs()->addPage([
            'id' => 'passkey',
            'label' => 'Passkeys',
            'order' => 100,
            'class' => 'Am_Form_Passkey',
        ]);
    }

    // Add passkey login button to member and admin login forms
    public function onAuthGetLoginForm(Am_Event_AuthGetLoginForm $event)
    {
        $form = $event->getForm();
        $form->addStatic('passkey_login')->setContent('<button type="button" id="passkey-login-btn">Login with Passkey</button>');
        // JS for passkey login will be added later
    }

    // Register hooks
    public function init()
    {
        parent::init();
        Am_Di::getInstance()->hook->add('userProfileTabs', [$this, 'onUserProfileTabs']);
        Am_Di::getInstance()->hook->add('authGetLoginForm', [$this, 'onAuthGetLoginForm']);
    Am_Di::getInstance()->hook->add('authControllerAction', [$this, 'onAuthControllerAction']);
    Am_Di::getInstance()->hook->add('afterRender', [$this, 'onAfterRender']);
    }
