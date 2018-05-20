<?php

namespace Firesphere\YubiAuth\Forms;

use Firesphere\BootstrapMFA\Forms\BootstrapMFALoginForm;
use LogicException;
use SilverStripe\Core\Environment;
use SilverStripe\Security\MemberAuthenticator\LoginHandler;

/**
 * Class YubikeyLoginForm
 * @package Firesphere\YubiAuth\Forms
 */
class YubikeyLoginForm extends BootstrapMFALoginForm
{

    /**
     * YubikeyLoginForm constructor.
     *
     * @param LoginHandler $handler
     * @param string $authenticatorClass
     * @param string $name
     * @param null $fields
     * @param null $actions
     * @param bool $checkCurrentUser
     * @throws \LogicException
     */
    public function __construct(
        $handler,
        $authenticatorClass,
        $name,
        $fields = null,
        $actions = null,
        $checkCurrentUser = true
    ) {
        if (!Environment::getEnv('YUBIAUTH_CLIENTID')) {
            throw new LogicException('YUBIAUTH_CLIENTID Must be enabled to use YubiAuth');
        }
        if (!Environment::getEnv('YUBIAUTH_APIKEY')) {
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
        return _t(self::class . '.TITLE', 'Yubikey Login');
    }
}
