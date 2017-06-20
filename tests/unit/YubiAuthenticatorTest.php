<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\YubikeyLoginForm;
use Firesphere\YubiAuth\YubikeyLoginHandler;
use Firesphere\YubiAuth\YubikeyMemberAuthenticator;
use PHPUnit_Framework_TestCase;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\Debug;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * Class YubiAuthenticatorTest
 *
 * @mixin PHPUnit_Framework_TestCase
 */
class YubiAuthenticatorTest extends SapphireTest
{

    protected static $fixture_file = '../fixtures/Member.yml';

    /**
     * @var YubikeyLoginHandler
     */
    protected $handler;
    /**
     * @var YubikeyLoginForm
     */
    protected $form;

    /**
     * @var YubikeyMemberAuthenticator
     */
    protected $authenticator;

    public function setUp()
    {
        parent::setUp();
        $this->objFromFixture(Member::class, 'admin');
        $validator = new MockYubiValidate('apikey', '1234');
        $this->authenticator = Injector::inst()->get(YubikeyMemberAuthenticator::class);
        $this->handler = Injector::inst()->get(YubikeyLoginHandler::class, true, [Security::login_url(), $this->authenticator]);
        Injector::inst()->registerService($validator, 'Yubikey\\Validate');
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testNoYubikey()
    {
        $this->handler->doLogin(
            [
                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
            ],
            null
        );
        $this->handler->validateYubikey(['yubiauth' => '']);
        $member = Security::getCurrentUser();
        $this->assertGreaterThan(0, $member->NoYubikeyCount);
        $this->assertEquals(null, $member->Yubikey);
    }

    public function testNoYubikeyLockout()
    {
        /** @var Member $member */
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $member->NoYubikeyCount = 25;
        $member->write();
        $failedLoginCount = $member->FailedLoginCount;
        $this->handler->doLogin(
            [

                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
            ],
            null
        );
        $this->handler->validateYubikey(['yubiauth' => '']);
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $this->assertGreaterThan($failedLoginCount, $member->FailedLoginCount);
    }

    public function testYubikey()
    {
        $this->handler->doLogin(
            [

                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
            ],
            null
        );
        $this->handler->validateYubikey([
            'yubiauth'  => 'jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn'
            // This OTP is _not_ valid in real situations
        ]);
        $result = Security::getCurrentUser();
        $this->assertEquals(Member::class, $result->ClassName);
        $this->assertEquals('ccccccfinfgr', $result->Yubikey);
        $this->assertEquals(1, $result->YubiAuthEnabled);
        $this->assertEquals('admin@silverstripe.com', $result->Email);
        $this->assertEquals(true, $result->YubiAuthEnabled);
        $result->write();
    }

    public function testYubikeyAfterSuccess()
    {
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $member->YubiAuthEnabled = true;
        $member->Yubikey = 'ccccccfinfgr';
        $member->NoYubikeyCount = 50;
        $member->write();
        Injector::inst()->get(IdentityStore::class)->logOut();
        $failedLoginCount = $member->FailedLoginCount;
        $this->handler->doLogin(
            [

                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
            ],
            null
        );
        $this->handler->validateYubikey([
            'yubiauth'  => ''
        ]);
        $resultNoYubi = Security::getCurrentUser();
        $this->assertEquals(null, $resultNoYubi);
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $this->assertGreaterThan($failedLoginCount, $member->FailedLoginCount);
    }

}
