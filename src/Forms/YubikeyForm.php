<?php

namespace Firesphere\YubiAuth\Forms;

use SilverStripe\Control\RequestHandler;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\FormAction;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\PasswordField;
use SilverStripe\Forms\RequiredFields;
use SilverStripe\Security\LoginForm;

/**
 * Class YubikeyForm
 * @package Firesphere\YubiAuth\Forms
 */
class YubikeyForm extends LoginForm
{
    /**
     * YubikeyForm constructor.
     * @param RequestHandler|null $controller
     * @param string $name
     */
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

    /**
     * @return FieldList|static
     */
    public function getFormFields()
    {
        $fields = FieldList::create(
            [
                PasswordField::create(
                    'yubiauth',
                    _t(self::class . '.YUBIKEYSECONDFACTORFIELD', 'Yubikey second factor authentication')
                )
            ]
        );
        $backURL = $this->controller->getRequest()->getVar('BackURL');
        if ($backURL) {
            $fields->push(HiddenField::create('BackURL', $backURL));
        }

        return $fields;
    }

    /**
     * @return FieldList|static
     */
    public function getFormActions()
    {
        $action = FieldList::create(
            [
                FormAction::create('validateToken', _t(self::class . '.VALIDATE', 'Validate'))
            ]
        );

        return $action;
    }

    /**
     * @return string
     */
    public function getAuthenticatorName()
    {
        return _t(self::class . '.TITLE', 'Yubikey authentication');
    }
}
