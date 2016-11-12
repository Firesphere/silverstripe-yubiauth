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
        parent::__construct($controller, $name, $fields, $actions, $checkCurrentUser);
        $this->Fields()->insertAfter('Password', PasswordField::create("Yubikey",
            _t('YubikeyAuthenticater.FORMFIELDNAME', 'Yubikey Authentication')));
        if (!SiteConfig::current_site_config()->RequirePassword) {
            $this->Fields()->removeByName('Password');
        }
    }

}
