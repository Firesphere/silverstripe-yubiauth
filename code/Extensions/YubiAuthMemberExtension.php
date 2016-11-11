<?php

/**
 * Class YubiAuthMemberExtension
 *
 * Enable yubikey authentication disabling temporarily
 */
class YubiAuthMemberExtension extends DataExtension
{

    private static $db = array(
        'YubiAuthEnabled' => 'Boolean(true)',
    );

    private static $defaults = array(
        'YubiAuthEnabled' => true
    );

    public function updateFieldLabels(&$labels) {
        parent::updateFieldLabels($labels);
        $labels['YubiAuthEnabled'] = _t('YubikeyAuthenticator.ENABLED', 'Yubikey Authentication Enabled');
    }

    public function updateCMSFields(FieldList $fields) {
        $fields->addFieldToTab('Root.Main', $yubiAuth = CheckboxField::create('YubiAuthEnabled', $this->owner->FieldLabel('YubiAuthEnabled')));
        $yubiAuth->setDescription('If the user is new and doesn\'t have a Yubikey yet, you can disable the auth temporarily');
    }

}