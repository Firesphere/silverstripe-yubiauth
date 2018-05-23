<?php

namespace Firesphere\YubiAuth;

use FieldList;
use MFAForm;
use PasswordField;
use RequiredFields;

/**
 * Class YubikeyForm
 * @package Firesphere\YubiAuth
 */
class YubikeyForm extends MFAForm
{
    /**
     * @return FieldList
     */
    public function getFormFields()
    {
        $fieldList = parent::getFormFields();
        $fieldList->push(PasswordField::create('Token', _t(__CLASS__ . '.Yubikey', 'Yubikey authentication')));

        return $fieldList;
    }

    /**
     * @return mixed|static
     */
    public function getRequiredFields()
    {
        return RequiredFields::create(['Token']);
    }
}
