<?php
/**
 * Created by PhpStorm.
 * User: simon
 * Date: 12-Nov-16
 * Time: 12:31
 */

namespace Firesphere\YubiAuth;


use CheckboxField;
use DataExtension;
use FieldList;
use NumericField;

class SiteConfigExtension extends DataExtension
{

    private static $db = array(
        'RequirePassword' => 'Boolean(true)',
        'MaxNoYubiLogins' => 'Int'
    );

    public function updateFieldLabels(&$labels)
    {
        parent::updateFieldLabels($labels);
        $labels['RequirePassword'] = 'Require a password on login';
        $labels['MaxNoYubiLogins'] = 'Maximum times a member may login without Yubikey';
    }

    /**
     * @param FieldList $fields
     */
    public function updateCMSFields(FieldList $fields)
    {
        parent::updateCMSFields($fields);
        $fields->addFieldToTab('Root.Access', $requirePass = CheckboxField::create('RequirePassword', $this->owner->fieldLabel('RequirePassword')));
        $fields->addFieldToTab('Root.Access', NumericField::create('MaxNoYubiLogins', $this->owner->fieldLabel('MaxNoYubiLogins')));
        $requirePass->setDisabled(true);
        $requirePass->setDescription(_t('YubikeyAuthenticator.NOTAVAILABLE', 'This option is not yet available'));
    }
}