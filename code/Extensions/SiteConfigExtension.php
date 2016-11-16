<?php

namespace Firesphere\YubiAuth;


use CheckboxField;
use DataExtension;
use FieldList;

class SiteConfigExtension extends DataExtension
{

    private static $db = array(
        'RequirePassword'    => 'Boolean(true)',
    );

    public function updateFieldLabels(&$labels)
    {
        parent::updateFieldLabels($labels);
        $labels['RequirePassword'] = _t('YubikeyAuthenticator.REQUIREPASSWORD', 'Require a password on login');
    }

    /**
     * @param FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
    {
        parent::updateCMSFields($fields);
        $requirePass = CheckboxField::create('RequirePassword', $this->owner->fieldLabel('RequirePassword'));
        $fields->addFieldToTab('Root.Access', $requirePass);
        $requirePass->setDisabled(true);
        $requirePass->setDescription(_t('YubikeyAuthenticator.NOTAVAILABLE', 'This option is not yet available'));
    }
}