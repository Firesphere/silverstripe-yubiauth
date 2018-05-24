<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\Providers\YubikeyAuthProvider;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use Yubikey\Validate;

class YubikeyAuthProviderTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/Member.yml';

    /**
     * @var YubikeyAuthProvider
     */
    protected $provider;

    public function testSetService()
    {
        $service = Injector::inst()->createWithArgs(Validate::class, ['test', 'test']);

        $this->provider->setService($service);

        $this->assertInstanceOf(Validate::class, $this->provider->getService());
    }

    public function testCheckNoYubikeyDaysZero()
    {
        Config::modify()->set(YubikeyAuthProvider::class, 'MaxNoYubiLoginDays', 0);
        /** @var Member $member */
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $member->Created = date('Y-m-d', strtotime('-1 year'));
        $member->MFAEnabled = false;
        $member->write();

        $result = $this->provider->checkNoYubiDays($member);
        $this->assertInstanceOf(Member::class, $result);
    }

    public function testCheckNoYubikeyDaysError()
    {
        /** @var Member $member */
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $member->Created = date('Y-m-d', strtotime('-1 year'));
        $member->MFAEnabled = false;
        $member->write();

        $result = $this->provider->checkNoYubiDays($member);
        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    public function testvalidateTokenDuplicate()
    {
        $result = Injector::inst()->get(ValidationResult::class, false);
        $member1 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => 'ccccccfinfgr',
            'MFAEnabled' => true
        ]);
        $member1->write();
        $member2 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '2@example.com',
            'Yubikey'    => 'ccccccfinfgr',
            'MFAEnabled' => true
        ]);
        $member2->write();

        $this->provider->validateToken($member1, 'ccccccfinfgr', $result);

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid());
    }

    public function testvalidateTokenID()
    {
        $result = Injector::inst()->get(ValidationResult::class, false);
        $member1 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => 'ccccccfinfgp',
            'MFAEnabled' => true
        ]);
        $member1->write();
        $member2 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '2@example.com',
            'Yubikey'    => 'ccccccfinfgr',
            'MFAEnabled' => true
        ]);
        $member2->write();

        $this->provider->validateToken($member1, 'ccccccfinfgr', $result);

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid());
    }

    public function testvalidateTokenNotMatchesMember()
    {
        $result = Injector::inst()->get(ValidationResult::class, false);
        $member1 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => 'ccccccfinfgr',
            'MFAEnabled' => true
        ]);
        $member1->write();

        $this->provider->validateToken($member1, '1234567890', $result);

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid());
    }

    public function testvalidateTokenUnique()
    {
        $result = Injector::inst()->get(ValidationResult::class, false);
        $member1 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => 'ccccccfinfgr',
            'MFAEnabled' => true
        ]);
        $member1->write();
        $member2 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '2@example.com',
            'Yubikey'    => 'ccccccfinfgp',
            'MFAEnabled' => true
        ]);
        $member2->write();

        $this->provider->validateToken($member1, 'ccccccfinfgr', $result);

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertTrue($result->isValid());
    }

    public function testSingleHost()
    {
        Config::modify()->set(YubikeyAuthProvider::class, 'AuthURL', 'localhost');

        /** @var YubikeyAuthProvider $provider */
        $provider = Injector::inst()->get(YubikeyAuthProvider::class, false);

        $url = $provider->getService()->getHost();

        $this->assertEquals('localhost', $url);
    }

    public function testHost()
    {
        Config::modify()->set(YubikeyAuthProvider::class, 'AuthURL', ['localhost-1', 'localhost-2']);

        /** @var YubikeyAuthProvider $provider */
        $provider = Injector::inst()->get(YubikeyAuthProvider::class, false);

        $url = $provider->getService()->getHost();

        $this->assertContains('localhost', $url);
    }

    public function testCheckYubikeyFalse()
    {
        $key = 'ccccccfinfgrtjhdeitnirlnggbicvnnthethdljlcvl';
        $result = Injector::inst()->get(ValidationResult::class, false);
        $member = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => 'ccccccfinfgr',
            'MFAEnabled' => true
        ]);
        $errorCount = $member->FailedLoginCount;
        $mockService = new MockYubiValidateFalse('key', 'secret');
        $this->provider->setService($mockService);
        $this->provider->checkYubikey(['yubiauth' => $key], $member, $result);

        $this->assertFalse($result->isValid());
        $this->assertGreaterThan($errorCount, $member->FailedLoginCount);
        $messages = $result->getMessages();
        $this->assertEquals('Yubikey authentication error', $messages[0]['message']);
    }

    public function testException()
    {
        $key = 'ccccccfinfgrtjhdeitnirlnggbicvnnthethdljlcvl';
        $result = Injector::inst()->get(ValidationResult::class, false);
        $member = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => 'ccccccfinfgr',
            'MFAEnabled' => true
        ]);
        $errorCount = $member->FailedLoginCount;
        $mockService = new MockYubiValidateException('key', 'secret');
        $this->provider->setService($mockService);
        $this->provider->checkYubikey(['yubiauth' => $key], $member, $result);

        $this->assertFalse($result->isValid());
        $this->assertGreaterThan($errorCount, $member->FailedLoginCount);
        $messages = $result->getMessages();
        $this->assertEquals('I do not like this', $messages[0]['message']);

    }

    protected function setUp()
    {
        $this->provider = Injector::inst()->get(YubikeyAuthProvider::class);

        return parent::setUp();
    }
}
