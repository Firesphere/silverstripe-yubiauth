<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\Authenticators\YubikeyMemberAuthenticator;
use Firesphere\YubiAuth\Forms\YubikeyLoginForm;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;

class YubikeyLoginFormTest extends SapphireTest
{

    /**
     * @expectedException \LogicException
     */
    public function testConstructClientID()
    {
        Environment::setEnv('YUBIAUTH_CLIENTID', '');
        YubikeyLoginForm::create(Controller::curr(), YubikeyMemberAuthenticator::class, 'test');
    }

    /**
     * @expectedException \LogicException
     */
    public function testConstruct()
    {
        Environment::setEnv('YUBIAUTH_APIKEY', '');
        YubikeyLoginForm::create(Controller::curr(), YubikeyMemberAuthenticator::class, 'test');
    }

    public function testAuthenticatorName()
    {
        $form = YubikeyLoginForm::create(Controller::curr(), YubikeyMemberAuthenticator::class, 'test');

        $this->assertEquals('Yubikey Login', $form->getAuthenticatorName());
    }
}
