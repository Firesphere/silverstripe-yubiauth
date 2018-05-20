<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\BootstrapMFA\Handlers\BootstrapMFALoginHandler;
use Firesphere\YubiAuth\Authenticators\YubikeyMemberAuthenticator;
use Firesphere\YubiAuth\Forms\YubikeyForm;
use Firesphere\YubiAuth\Forms\YubikeyLoginForm;
use Firesphere\YubiAuth\Handlers\YubikeyLoginHandler;
use Firesphere\YubiAuth\Providers\YubikeyAuthProvider;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use Yubikey\Validate;

class YubikeyMemberAuthenticatorTest extends SapphireTest
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
        Injector::inst()->registerService($validator, Validate::class);
        $this->authenticator = Injector::inst()->get(YubikeyMemberAuthenticator::class);
        $this->handler = Injector::inst()->createWithArgs(
            YubikeyLoginHandler::class,
            [Security::login_url(), $this->authenticator]
        );
        $this->form = Injector::inst()->get(
            YubikeyLoginForm::class,
            true,
            [$this->handler, YubikeyMemberAuthenticator::class, '']
        );
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
        $this->handler->validateToken(
            ['yubiauth' => ''],
            YubikeyForm::create($this->handler),
            $request
        );
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $this->assertGreaterThan(0, (int)$member->NoYubikeyCount);
        $this->assertEquals(null, $member->Yubikey);
    }

    public function testNoYubikeySuccess()
    {
        /** @var Member $member */
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $member->NoYubikeyCount = 0;
        $member->MFAEnabled = false;
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
        $this->handler->validateToken(
            ['yubiauth' => ''],
            YubikeyForm::create($this->handler),
            $request
        );
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $this->assertEquals(0, $member->FailedLoginCount);
    }

    public function testNoYubikeyLockout()
    {
        /** @var Member $member */
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $failedCount = $member->FailedLoginCount;
        $member->NoYubikeyCount = 25;
        $member->MFAEnabled = false;
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
        $result = $this->handler->validateToken(
            ['yubiauth' => ''],
            YubikeyForm::create($this->handler),
            $request
        );
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $this->assertGreaterThan($failedCount, $member->FailedLoginCount);
    }

    public function testNoYubikeyDays()
    {
        /** @var Member $member */
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $failedCount = $member->FailedLoginCount;
        $member->NoYubikeyCount = 26;
        $member->Created = date('Y-m-d', strtotime('-1 year'));
        $member->MFAEnabled = false;
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
        $result = $this->handler->validateToken(
            ['yubiauth' => ''],
            YubikeyForm::create($this->handler),
            $request
        );
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $this->assertGreaterThan($failedCount, $member->FailedLoginCount);
    }

    public function testYubikeyAfterSuccess()
    {
        $request = new HTTPRequest('POST', '/');
        $request->setSession(new Session(['hi' => 'bye']));
        $this->handler->setRequest($request);
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $member->MFAEnabled = true;
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
        $this->handler->validateToken(['yubiauth' => ''], YubikeyForm::create($this->handler), $request);
        $resultNoYubi = Security::getCurrentUser();
        $this->assertEquals(null, $resultNoYubi);
        $member = Member::get()->filter(array('Email' => 'admin@silverstripe.com'))->first();
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
        $this->handler->validateToken(
            [
                // This OTP is _not_ valid in real situations
                'yubiauth' => 'jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn'
            ],
            YubikeyForm::create($this->handler),
            $request
        );

        $result = Security::getCurrentUser();
        $this->assertEquals(Member::class, $result->ClassName);
        $this->assertEquals('ccccccfinfgr', $result->Yubikey);
        $this->assertEquals(1, $result->MFAEnabled);
        $this->assertEquals('admin@silverstripe.com', $result->Email);
    }

    public function testName()
    {
        $this->assertEquals('Yubikey 2 factor login', YubikeyMemberAuthenticator::get_name());
    }

    public function testGetLoginHandler()
    {
        $authenticator = new YubikeyMemberAuthenticator();

        $handler = $authenticator->getLoginHandler(Security::login_url());

        $this->assertInstanceOf(YubikeyLoginHandler::class, $handler);
    }

    public function testGetSetProvider()
    {
        /** @var YubikeyMemberAuthenticator $authenticator */
        $authenticator = new YubikeyMemberAuthenticator();

        /** @var YubikeyAuthProvider $provider */
        $provider = Injector::inst()->get(YubikeyAuthProvider::class);

        $authenticator->setProvider($provider);

        $this->assertInstanceOf(YubikeyAuthProvider::class, $authenticator->getProvider());
    }

    public function testSupportedServices()
    {
        /** @var YubikeyMemberAuthenticator $authenticator */
        $authenticator = new YubikeyMemberAuthenticator();

        $this->assertEquals(47, $authenticator->supportedServices());
    }

    public function testUnknownMember()
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
        $session = $request->getSession();
        $session->set(BootstrapMFALoginHandler::SESSION_KEY . '.MemberID', -100);
        $request->setSession($session);

        $this->authenticator->validateToken(
            [],
            $request,
            $result
        );

        $this->assertFalse($result->isValid());
    }
}
