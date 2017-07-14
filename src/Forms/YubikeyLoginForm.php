<?php

namespace Firesphere\YubiAuth;

use Firesphere\BootstrapMFA\MFALoginForm;
use LogicException;
use SilverStripe\Security\MemberAuthenticator\LoginHandler;

class YubikeyLoginForm extends MFALoginForm
{

    /**
     * YubikeyLoginForm constructor.
     *
     * @param LoginHandler $handler
     * @param string       $name
     * @param null         $fields
     * @param null         $actions
     * @param bool         $checkCurrentUser
     */
    public function __construct(
        $handler,
        $authenticatorClass,
        $name,
        $fields = null,
        $actions = null,
        $checkCurrentUser = true
    ) {
        if (!getenv('YUBIAUTH_CLIENTID')) {
            throw new LogicException('YUBIAUTH_CLIENTID Must be enabled to use YubiAuth');
        }
        if (!getenv('YUBIAUTH_APIKEY')) {
            throw new LogicException('YUBIAUTH_APIKEY Must be enabled to use YubiAuth');
        }

        parent::__construct($handler, $authenticatorClass, $name, $fields, $actions, $checkCurrentUser);
    }

    /**
     * Title of the login form
     *
     * @return string
     */
    public function getAuthenticatorName()
    {
        return _t('YubikeyLoginForm.TITLE', 'Yubikey Login');
    }

}
