<?php

namespace Firesphere\YubiAuth;

use SilverStripe\Control\RequestHandler;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\PasswordField;
use SilverStripe\Forms\RequiredFields;
use SilverStripe\Security\LoginForm;

class YubikeyForm extends LoginForm
{
    public function __construct(
        RequestHandler $controller = null,
        $name = self::DEFAULT_NAME
    ) {
        $this->controller = $controller;
        $fields = $this->getFormFields();
        $actions = $this->getFormActions();
        $validator = RequiredFields::create(['yubiauth']);

        parent::__construct($controller, $name, $fields, $actions, $validator);
    }

    public function getFormFields()
    {
        $fields = FieldList::create(
            [
                PasswordField::create('yubiauth', 'Yubikey second factor authentication')
            ]
        );
        $backURL = $this->controller->getRequest()->getVar('BackURL');
        if ($backURL) {
            $fields->push(HiddenField::create('BackURL', $backURL));
        }

        return $fields;
    }

    public function getFormActions()
    {
        $action = FieldList::create(
            [
                FormAction::create('validateYubikey', 'Validate')
            ]
        );

        return $action;
    }

    public function getAuthenticatorName()
    {
        return _t('YubikeyLoginForm.TITLE', 'Yubikey authentication');
    }
}
