<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\Providers\YubikeyAuthProvider;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

class YubikeyAuthProviderTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/Member.yml';

    /**
     * @var YubikeyAuthProvider
     */
    protected $provider;

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
        $member1 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => '1234567890',
            'MFAEnabled' => true
        ]);
        $member1->write();
        $member2 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '2@example.com',
            'Yubikey'    => '1234567890',
            'MFAEnabled' => true
        ]);
        $member2->write();

        $result = $this->provider->validateToken($member1, '1234567890');

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid());
    }

    public function testvalidateTokenID()
    {
        $member1 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => '0987654321',
            'MFAEnabled' => true
        ]);
        $member1->write();
        $member2 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '2@example.com',
            'Yubikey'    => '1234567890',
            'MFAEnabled' => true
        ]);
        $member2->write();

        $result = $this->provider->validateToken($member1, '1234567890');

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid());
    }

    public function testvalidateTokenNotMatchesMember()
    {
        $member1 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => 'abcdefghij',
            'MFAEnabled' => true
        ]);
        $member1->write();

        $result = $this->provider->validateToken($member1, '1234567890');

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertFalse($result->isValid());
    }

    public function testvalidateTokenUnique()
    {
        $member1 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => 'abcdefghij',
            'MFAEnabled' => true
        ]);
        $member1->write();
        $member2 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '2@example.com',
            'Yubikey'    => '1234567890',
            'MFAEnabled' => true
        ]);
        $member2->write();

        $result = $this->provider->validateToken($member1, 'abcdefghij');

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertTrue($result->isValid());
    }

    protected function setUp()
    {
        $this->provider = Injector::inst()->get(YubikeyAuthProvider::class);

        return parent::setUp();
    }
}
