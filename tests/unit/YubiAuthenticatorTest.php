<?php

namespace Firesphere\YubiAuth\Tests;

use Authenticator;
use Config;
use Firesphere\YubiAuth\YubikeyAuthenticator;
use Firesphere\YubiAuth\YubikeyLoginForm;
use Injector;
use Member;
use PHPUnit_Framework_TestCase;
use SapphireTest;
use Security;

/**
 * Class YubiAuthenticatorTest
 *
 * @mixin PHPUnit_Framework_TestCase
 */
class YubiAuthenticatorTest extends SapphireTest
{

    protected static $fixture_file = '../fixtures/Member.yml';

    /**
     * @var YubikeyLoginForm
     */
    protected $form;

    public function setUp()
    {
        parent::setUp();
        $this->objFromFixture('Member', 'admin');
        $controller = Security::create();
        /** @var YubikeyLoginForm $form */
        $this->form = YubikeyLoginForm::create($controller, 'Form', null, null);
        Authenticator::register_authenticator('Firesphere\\YubiAuth\\YubikeyAuthenticator');
        $validator = new MockYubiValidate('apikey', '1234');
        Injector::inst()->registerService($validator, 'Yubikey\\Validate');
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testNoYubikey()
    {
        $member = YubikeyAuthenticator::authenticate(array(
            'Email' => 'admin@silverstripe.com',
            'Password' => 'password',
            'Yubikey' => ''
        ), $this->form);
        $this->assertGreaterThan(0, $member->NoYubikeyCount);
        $this->assertEquals(null, $member->Yubikey);
    }

    public function testNoYubikeyLockout()
    {
        Config::inst()->update('Firesphere\\YubiAuth\\YubikeyAuthenticator', 'MaxNoYubiLogin', 5);
        /** @var Member $member */
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $member->NoYubikeyCount = 5;
        $member->write();
        $failedLoginCount = $member->FailedLoginCount;
        $result = YubikeyAuthenticator::authenticate(array(
            'Email' => 'admin@silverstripe.com',
            'Password' => 'password',
            'Yubikey' => ''
        ), $this->form);
        $this->assertEquals(null, $result);
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $this->assertGreaterThan($failedLoginCount, $member->FailedLoginCount);
    }

    public function testYubikey()
    {
        $result = YubikeyAuthenticator::authenticate(array(
            'Email' => 'admin@silverstripe.com',
            'Password' => 'password',
            'Yubikey' => 'jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn' // This OTP is _not_ valid in real situations
        ), $this->form);
        $this->assertEquals('Member', $result->ClassName);
        $this->assertEquals('ccccccfinfgr', $result->Yubikey);
        $this->assertEquals('admin@silverstripe.com', $result->Email);
        $this->assertEquals(true, $result->YubiAuthEnabled);
    }

    public function testYubikeyRequiredButNotUsed()
    {
        /** @var Member $member */
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $member->YubiAuthEnabled = true;
        $member->write();
        $failedLoginCount = $member->FailedLoginCount;
        $resultNoYubi = YubikeyAuthenticator::authenticate(array(
            'Email' => 'admin@silverstripe.com',
            'Password' => 'password',
            'Yubikey' => ''
        ), $this->form);
        $this->assertEquals(null, $resultNoYubi);
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $this->assertGreaterThan($failedLoginCount, $member->FailedLoginCount);
    }

}