<?php

namespace Firesphere\YubiAuth;

use SilverStripe\Core\Extensible;
use SilverStripe\Forms\CheckboxField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\NumericField;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\ORM\DataExtension;

/**
 * Class YubiAuthMemberExtension
 * 
 * Enable yubikey authentication disabling temporarily
 *
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
        $fields->removeByName(['NoYubikeyCount', 'Yubikey', 'YubiAuthEnabled']);
        $yubiCount = NumericField::create('NoYubikeyCount', $this->owner->fieldLabel('NoYubikeyCount'));
        if ($this->owner->YubiAuthEnabled) {
            $yubiCount->setReadonly(true);
        }
        $yubiField = ReadonlyField::create('Yubikey', $this->owner->fieldLabel('Yubikey'));
        $yubiField->setDescription(
            _t(
                'YubikeyAuthenticator.YUBIKEYDESCRIPTION',
                'Unique identifier string for the Yubikey. Will reset when the Yubikey Authentication is disabled'
            )
        );

        $yubiAuth = CheckboxField::create('YubiAuthEnabled', $this->owner->fieldLabel('YubiAuthEnabled'));
        $yubiAuth->setDescription(
            _t(
                'YubikeyAuthenticator.ENABLEDDESCRIPTION',
                'If the user is new and doesn\'t have a Yubikey yet, you can disable the auth temporarily'
            )
        );

        $fields->addFieldsToTab('Root.Main', [$yubiCount, $yubiField, $yubiAuth], 'DirectGroups');

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
