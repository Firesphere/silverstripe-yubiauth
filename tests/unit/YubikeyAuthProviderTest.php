<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\Providers\YubikeyAuthProvider;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\Debug;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

class YubikeyAuthProviderTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/Member.yml';

    /** 
     * @var ValidationResult 
     */
    protected $result;
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

        $this->provider->validateToken($member1, '1234567890', $this->result);

        $this->assertInstanceOf(ValidationResult::class, $this->result);
        $this->assertFalse($this->result->isValid());
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

        $this->provider->validateToken($member1, '1234567890', $this->result);

        $this->assertInstanceOf(ValidationResult::class, $this->result);
        $this->assertFalse($this->result->isValid());
    }

    public function testvalidateTokenNotMatchesMember()
    {
        $member1 = Member::create([
            'Email'      => 'user' . uniqid('', false) . '1@example.com',
            'Yubikey'    => 'abcdefghij',
            'MFAEnabled' => true
        ]);
        $member1->write();

        $this->provider->validateToken($member1, '1234567890', $this->result);

        $this->assertInstanceOf(ValidationResult::class, $this->result);
        $this->assertFalse($this->result->isValid());
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

        $this->provider->validateToken($member1, 'abcdefghij', $this->result);

        $this->assertInstanceOf(ValidationResult::class, $this->result);
        $this->assertTrue($this->result->isValid());
    }

    protected function setUp()
    {
        $this->provider = Injector::inst()->get(YubikeyAuthProvider::class);
        $this->result = Injector::inst()->get(ValidationResult::class);
        return parent::setUp();
    }
}
