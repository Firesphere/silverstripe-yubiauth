<?php
namespace Firesphere\YubiAuth;

use CheckboxField;
use DataExtension;
use FieldList;
use Member;
use ReadonlyField;
use TextField;

/**
 * Class YubiAuthMemberExtension
 * 
 * Enable yubikey authentication disabling temporarily
 *
 * @property Member|MemberExtension $owner
 * @property boolean $YubiAuthEnabled
 * @property string $Yubikey
 * @property int $NoYubikeyCount
 */
class MemberExtension extends DataExtension
{

    private static $db = array(
        'YubiAuthEnabled' => 'Boolean(true)',
        'Yubikey'         => 'Varchar(16)',
        'NoYubikeyCount'  => 'Int'
    );

    private static $defaults = array(
        'YubiAuthEnabled' => true
    );

    private static $indexes = array(
        'Yubikey' => 'unique("Yubikey")' // The Yubikey Signature is unique for every Yubikey.
    );

    /**
     * @inheritdoc
     * @param array $labels
     */
    public function updateFieldLabels(&$labels)
    {
        parent::updateFieldLabels($labels);
        $labels['YubiAuthEnabled'] = _t('YubikeyAuthenticator.ENABLED', 'Yubikey Authentication Enabled');
        $labels['Yubikey'] = _t('YubikeyAuthenticator.YUBIKEY', 'Yubikey code');
        $labels['NoYubikeyCount'] = _t('YubikeyAuthenticator.NOYUBIKEYCOUNT', 'Login count without yubikey');
    }

    /**
     * @inheritdoc
     * @param FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
    {
        $fields->addFieldToTab('Root.Main', ReadonlyField::create('NoYubikeyCount', $this->owner->fieldLabel('NoYubikeyCount')));
        $yubiField = TextField::create('Yubikey', $this->owner->fieldLabel('Yubikey'));
        if ($this->owner->Yubikey) {
            // Disable editing the field when a key is set, so it's harder to tamper with
            $yubiField->setReadonly(true); // Will be filled the first time the user uses his/her yubikey
        }
        $yubiField->setDescription(_t('YubikeyAuthenticator.YUBIKEYDESCRIPTION',
            'Unique identifier string for the Yubikey'));
        $fields->addFieldToTab('Root.Main', $yubiField);

        $fields->addFieldToTab('Root.Main',
            $yubiAuth = CheckboxField::create('YubiAuthEnabled', $this->owner->FieldLabel('YubiAuthEnabled')));
        $yubiAuth->setDescription(_t('YubikeyAuthenticator.ENABLEDDESCRIPTION',
            'If the user is new and doesn\'t have a Yubikey yet, you can disable the auth temporarily'));
    }

    /**
     * @inheritdoc
     */
    public function onBeforeWrite()
    {
        // Empty the yubikey field on member write, if the yubiauth is not required
        // Maybe the user lost the key? So a new one will be set next time it's logged in with key
        if (!$this->owner->YubiAuthEnabled) {
            $this->owner->Yubikey = '';
        }
    }

}