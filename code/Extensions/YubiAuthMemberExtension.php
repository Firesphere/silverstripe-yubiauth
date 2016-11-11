<?php
namespace Firesphere\YubiAuth;
use CheckboxField;
use DataExtension;
use FieldList;
use TextField;

/**
 * Class YubiAuthMemberExtension
 *
 * Enable yubikey authentication disabling temporarily
 */
class YubiAuthMemberExtension extends DataExtension
{

    private static $db = array(
        'YubiAuthEnabled' => 'Boolean(true)',
        'Yubikey' => 'Varchar(16)'
    );

    private static $defaults = array(
        'YubiAuthEnabled' => true
    );

    private static $indexes = array(
        'Yubikey' => 'unique("Yubikey")'
    );

    public function updateFieldLabels(&$labels) {
        parent::updateFieldLabels($labels);
        $labels['YubiAuthEnabled'] = _t('YubikeyAuthenticator.ENABLED', 'Yubikey Authentication Enabled');
        $labels['Yubikey'] = _t('YubikeyAuthenticator.YUBIKEY', 'Yubikey code');
    }

    public function updateCMSFields(FieldList $fields) {
        $yubiField = TextField::create('Yubikey', $this->owner->fieldLabel('Yubikey'));
        $yubiField->setReadonly(true); // Will be filled the first time the user uses his/her yubikey
        $yubiField->setDescription(_t('YubikeyAuthenticator.YUBIKEYDESCRIPTION', 'Unique identifier string for the Yubikey'));
        $fields->addFieldToTab('Root.Main', $yubiField);

        $fields->addFieldToTab('Root.Main', $yubiAuth = CheckboxField::create('YubiAuthEnabled', $this->owner->FieldLabel('YubiAuthEnabled')));
        $yubiAuth->setDescription(_t('YubikeyAuthenticator.ENABLEDDESCRIPTION', 'If the user is new and doesn\'t have a Yubikey yet, you can disable the auth temporarily'));
    }

}