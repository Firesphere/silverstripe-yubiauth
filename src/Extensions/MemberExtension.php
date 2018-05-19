<?php

namespace Firesphere\YubiAuth\Extensions;

use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\NumericField;
use SilverStripe\ORM\DataExtension;

/**
 * Class YubiAuthMemberExtension
 *
 * Enable yubikey authentication disabling temporarily
 *
 * @property \Firesphere\YubiAuth\Extensions\MemberExtension $owner
 * @property string $Yubikey
 * @property int $NoYubikeyCount
 */
class MemberExtension extends DataExtension
{
    private static $db = [
        'Yubikey'        => 'Varchar(255)',
        'NoYubikeyCount' => 'Int'
    ];

    /**
     * @inheritdoc
     * @param array $labels
     */
    public function updateFieldLabels(&$labels)
    {
        $labels['Yubikey'] = _t('YubikeyAuthenticator.YUBIKEY', 'Yubikey code');
        $labels['NoYubikeyCount'] = _t('YubikeyAuthenticator.NOYUBIKEYCOUNT', 'Login count without yubikey');
    }

    /**
     * @inheritdoc
     * @param FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
    {
        $fields->removeByName(['NoYubikeyCount', 'Yubikey']);
        $yubiCount = NumericField::create('NoYubikeyCount');

        $fields->addFieldsToTab('Root.MFA', [$yubiCount]);

        return $fields;
    }

    /**
     * @inheritdoc
     */
    public function onBeforeWrite()
    {
        // Empty the yubikey field on member write, if the yubiauth is not required
        // Maybe the user lost the key? So a new one will be set next time it's logged in with key
        if (!$this->owner->MFAEnabled) {
            $this->owner->Yubikey = '';
        }
    }
}
