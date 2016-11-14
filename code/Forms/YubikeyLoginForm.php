<?php
namespace Firesphere\YubiAuth;

use MemberLoginForm;
use PasswordField;
use SiteConfig;

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
        parent::__construct($controller, $name, $fields, $actions, $checkCurrentUser);

        $this->Fields()->insertAfter('Password', PasswordField::create("Yubikey",
            _t('YubikeyAuthenticater.FORMFIELDNAME', 'Yubikey Authentication')));

        if (!SiteConfig::current_site_config()->RequirePassword) {
            $this->Fields()->removeByName('Password');
        }
    }

}
