<?php
class Am_Plugin_Testhook extends Am_Plugin
{
    protected $id = 'testhook';
    protected $title = 'Test Hook Plugin';
    protected $description = 'Test plugin to verify aMember hook firing.';

    public function __construct($config, $id)
    {
        parent::__construct($config, $id);
        Am_Di::getInstance()->hook->add('setupForms', [$this, 'onSetupForms']);
        Am_Di::getInstance()->hook->add('userProfile', [$this, 'onUserProfile']);
    }

    public function onSetupForms($event)
    {
        error_log('Testhook plugin: onSetupForms called');
        $form = new Am_Form_Setup('testhook');
        $form->setTitle('Test Hook Plugin');
        $form->addHtml('<!-- Testhook plugin: onSetupForms marker -->');
        $event->addForm($form);
    }

    public function onUserProfile($event)
    {
        error_log('Testhook plugin: onUserProfile called');
        $form = $event->getForm();
        $form->addHtml('<!-- Testhook plugin: onUserProfile marker -->');
    }
}
