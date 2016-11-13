<?php

use Firesphere\YubiAuth\YubikeyAuthenticator;
use Firesphere\YubiAuth\YubikeyLoginForm;

class YubiAuthenticatorTest extends SapphireTest
{

    protected static $fixture_file = '../fixtures/Member.yml';

    protected $form;

    public function setUp()
    {
        parent::setUp();
        $this->objFromFixture('Member', 'admin');
        $controller = Security::create();
        /** @var YubikeyLoginForm $form */
        $this->form = YubikeyLoginForm::create($controller, 'Form', null, null);
        Authenticator::register_authenticator('Firesphere\\YubiAuth\\YubikeyAuthenticator');
    }

    public function tearDown()
    {
        parent::tearDown(); // TODO: Change the autogenerated stub
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
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $member->NoYubikeyCount = 5;
        $member->write();
        $result = YubikeyAuthenticator::authenticate(array(
            'Email' => 'admin@silverstripe.com',
            'Password' => 'password',
            'Yubikey' => ''
        ), $this->form);
        $this->assertEquals(null, $result);
    }

    public function testYubikey()
    {
        $validator = new MockYubiValidate('apikey', '1234');
        Injector::inst()->registerService($validator, 'Yubikey\\Validate');
        $result = YubikeyAuthenticator::authenticate(array(
            'Email' => 'admin@silverstripe.com',
            'Password' => 'password',
            'Yubikey' => 'jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn' // This OTP is _not_ valid in real situations
        ), $this->form);
        $this->assertEquals('Member', $result->ClassName);
        $this->assertEquals('ccccccfinfgr', $result->Yubikey);
        $this->assertEquals(true, $result->YubiAuthEnabled);
        $resultNoYubi = YubikeyAuthenticator::authenticate(array(
            'Email' => 'admin@silverstripe.com',
            'Password' => 'password',
            'Yubikey' => ''
        ), $this->form);
        $this->assertEquals(null, $resultNoYubi);
    }

    public function testReplayedOTP()
    {
        $validator = new MockYubiValidate('apikey', '1234', array(), true);
        Injector::inst()->registerService($validator, 'Yubikey\\Validate');
        $result = YubikeyAuthenticator::authenticate(array(
            'Email' => 'admin@silverstripe.com',
            'Password' => 'password',
            'Yubikey' => 'jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn'
        ), $this->form);
        $this->assertEquals(null, $result);
    }
}