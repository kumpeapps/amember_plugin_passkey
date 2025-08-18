<?php
/**
 * User Passkey Management Form
 */
class Am_Form_Passkey extends Am_Form
{
    public function __construct()
    {
        parent::__construct('form-passkey');
        $this->setLabel('Manage Passkeys');
    }

    public function init()
    {
        $this->addStatic('info')->setContent('<p>You can register and manage your passkeys (FIDO2/WebAuthn) here.</p>');
        $this->addStatic('register_btn')->setContent('<button type="button" id="register-passkey-btn">Register New Passkey</button>');
        $this->addStatic('list')->setContent('<div id="passkey-list"></div>');
        // JS for passkey registration and management will be added later
    }
}
