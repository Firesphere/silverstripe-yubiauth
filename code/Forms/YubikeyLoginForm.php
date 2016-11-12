<?php
namespace Firesphere\YubiAuth;

use CheckboxField;
use FieldList;
use HiddenField;
use Member;
use MemberLoginForm;
use PasswordField;
use Security;
use SiteConfig;
use TextField;
use Injector;

class YubikeyLoginForm extends MemberLoginForm
{

    protected $authenticator_class = 'Firesphere\\YubiAuth\\YubikeyAuthenticator';

    /**
     * @inheritdoc
     */
    public function __construct(
        $controller,
        $name,
        $fields = null,
        $actions = null,
        $checkCurrentUser = true
    ) {
        if ($checkCurrentUser && Member::currentUser() && Member::logged_in_session_exists()) {
            parent::__construct($controller, $name, $fields, $actions);
        } else {
            $label = Injector::inst()->get('Member')->fieldLabel(Member::config()->unique_identifier_field);
            if (!$fields) {
                $fieldArray = array(
                    $emailField = TextField::create("Email", $label, null, null, $this),
                    HiddenField::create("AuthenticationMethod", null, $this->authenticator_class, $this),
                    //Regardless of what the unique identifer field is (usually 'Email'), it will be held in the 'Email' value, below:
                    PasswordField::create("Password", _t('Member.PASSWORD', 'Password')),
                    PasswordField::create("Yubikey", _t('YubikeyAuthenticater.FORMFIELDNAME', 'Yubikey Authentication'))
                );
                if(!SiteConfig::current_site_config()->RequirePassword) {
                    unset($fieldArray[2]);
                }
                $fields = FieldList::create(
                    $fieldArray
                );
                if (Security::config()->autologin_enabled) {
                    $fields->push(CheckboxField::create(
                        "Remember",
                        _t('Member.REMEMBERME', "Remember me next time?")
                    ));
                }
            }
        }

        parent::__construct($controller, $name, $fields, $actions);
    }

}
