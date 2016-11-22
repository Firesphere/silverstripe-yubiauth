<?php
namespace Firesphere\YubiAuth;

use MemberLoginForm;
use PasswordField;
use SiteConfig;

class YubikeyLoginForm extends MemberLoginForm
{

    /**
     * Setup the yubikey authentication after generating the standard loginform.
     *
     * @inheritdoc
     */
    public function __construct(
        $controller,
        $name,
        $fields = null,
        $actions = null,
        $checkCurrentUser = true
    ) {
        $this->authenticator_class = 'Firesphere\\YubiAuth\\YubikeyAuthenticator';
        parent::__construct($controller, $name, $fields, $actions, $checkCurrentUser);

        $this->Fields()->insertAfter('Password', PasswordField::create("Yubikey",
            _t('YubikeyAuthenticater.FORMFIELDNAME', 'Yubikey Authentication')));

        if (!SiteConfig::current_site_config()->RequirePassword) {
            $this->Fields()->removeByName(array('Password', 'forgotPassword'));
        }
    }

}
