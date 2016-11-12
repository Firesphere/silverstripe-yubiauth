<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\YubikeyLoginForm;
use Firesphere\YubiAuth\YubikeyMemberAuthenticator;
use PHPUnit_Framework_TestCase;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
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
     * @var YubikeyLoginForm
     */
    protected $form;

    public function setUp()
    {
        parent::setUp();
        $this->objFromFixture(Member::class, 'admin');
        $controller = Security::create();
        /** @var YubikeyLoginForm $form */
        $this->form = YubikeyLoginForm::create($controller, YubikeyMemberAuthenticator::class, 'LoginForm', null, null);
        $validator = new MockYubiValidate('apikey', '1234');
        Injector::inst()->registerService($validator, 'Yubikey\\Validate');
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testNoYubikey()
    {
        $member = YubikeyMemberAuthenticator::singleton()->authenticate(
            [
                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
                'Yubikey'  => ''
            ],
            $this->form
        );
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
        $result = YubikeyMemberAuthenticator::singleton()->authenticate(
            [

                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
                'Yubikey'  => ''
            ],
            $this->form
        );
        $this->assertEquals(null, $result);
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $this->assertGreaterThan($failedLoginCount, $member->FailedLoginCount);
    }

    public function testYubikey()
    {
        $result = YubikeyMemberAuthenticator::singleton()->authenticate(
            [
                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
                'Yubikey'  => 'jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn'
                // This OTP is _not_ valid in real situations
            ],
            $this->form
        );
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
        $failedLoginCount = $member->FailedLoginCount;
        $resultNoYubi = YubikeyMemberAuthenticator::singleton()->authenticate(
            [
                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
                'Yubikey'  => ''
            ],
            $this->form
        );
        $this->assertEquals(null, $resultNoYubi);
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $this->assertGreaterThan($failedLoginCount, $member->FailedLoginCount);
    }

}