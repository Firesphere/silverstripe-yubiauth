<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\YubikeyForm;
use Firesphere\YubiAuth\YubikeyLoginForm;
use Firesphere\YubiAuth\YubikeyLoginHandler;
use Firesphere\YubiAuth\YubikeyMemberAuthenticator;
use PHPUnit_Framework_TestCase;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use Yubikey\Validate;

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

    protected $request;

    public function setUp()
    {
        parent::setUp();
        $this->objFromFixture(Member::class, 'admin');
        $validator = new MockYubiValidate('apikey', '1234');
        $this->authenticator = Injector::inst()->get(YubikeyMemberAuthenticator::class);
        $this->handler = Injector::inst()->createWithArgs(YubikeyLoginHandler::class,
            [Security::login_url(), $this->authenticator]);
        $this->form = Injector::inst()->get(
            YubikeyLoginForm::class,
            true,
            [$this->handler, YubikeyMemberAuthenticator::class, '']
        );
        Injector::inst()->registerService($validator, Validate::class);
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testNoYubikey()
    {
        $request = new HTTPRequest('POST', '/');
        $request->setSession(new Session(['hi' => 'bye']));
        $this->handler->setRequest($request);

        $this->handler->doLogin(
            [
                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
            ],
            $this->form,
            $request
        );
        $this->handler->validateYubikey(
            ['yubiauth' => ''],
            YubikeyForm::create($this->handler),
            $request
        );
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $this->assertGreaterThan(0, $member->NoYubikeyCount);
        $this->assertEquals(null, $member->Yubikey);
    }

    public function testNoYubikeyLockout()
    {
        /** @var Member $member */
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $failedLoginCount = $member->FailedLoginCount;
        $member->NoYubikeyCount = 25;
        $member->write();
        $request = new HTTPRequest('POST', '/');
        $request->setSession(new Session(['hi' => 'bye']));
        $this->handler->setRequest($request);
        $this->handler->doLogin(
            [

                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
            ],
            $this->form,
            $request
        );
        $this->handler->validateYubikey(
            ['yubiauth' => ''],
            YubikeyForm::create($this->handler),
            $request
        );
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $this->assertGreaterThan($failedLoginCount, $member->FailedLoginCount);
    }

    public function testYubikey()
    {
        $request = new HTTPRequest('POST', '/');
        $request->setSession(new Session(['hi' => 'bye']));
        $this->handler->setRequest($request);
        $this->handler->doLogin(
            [

                'Email'    => 'admin@silverstripe.com',
                'Password' => 'password',
            ],
            $this->form,
            $request
        );
        $this->handler->validateYubikey([
            // This OTP is _not_ valid in real situations
            'yubiauth' => 'jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn'
        ],
            YubikeyForm::create($this->handler),
            $request
        );
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
        $request = new HTTPRequest('POST', '/');
        $request->setSession(new Session(['hi' => 'bye']));
        $this->handler->setRequest($request);
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
            $this->form,
            $request
        );
        $this->handler->validateYubikey(['yubiauth' => ''], YubikeyForm::create($this->handler), $request);
        $resultNoYubi = Security::getCurrentUser();
        $this->assertEquals(null, $resultNoYubi);
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
        $this->assertGreaterThan($failedLoginCount, $member->FailedLoginCount);
    }

}
