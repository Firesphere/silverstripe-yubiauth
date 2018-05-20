<?php

namespace Firesphere\YubiAuth\Providers;

use DateTime;
use Exception;
use Firesphere\BootstrapMFA\Providers\BootstrapMFAProvider;
use Firesphere\BootstrapMFA\Providers\MFAProvider;
use Firesphere\YubiAuth\Helpers\QwertyConvertor;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use Yubikey\Response;
use Yubikey\Validate;

/**
 * Class YubikeyAuthProvider
 *
 * @package Firesphere\YubiAuth
 */
class YubikeyAuthProvider extends BootstrapMFAProvider implements MFAProvider
{
    use Configurable;

    /**
     * @var Validate
     */
    protected $service;

    /**
     * Setup
     */
    public function __construct()
    {
        /** @var Validate $service */
        $this->service = Injector::inst()->createWithArgs(
            Validate::class,
            [
                Environment::getEnv('YUBIAUTH_APIKEY'),
                Environment::getEnv('YUBIAUTH_CLIENTID'),
            ]
        );

        if ($url = Config::inst()->get(static::class, 'AuthURL')) {
            $url = (array)$url;
            $this->service->setHosts($url);
        }
    }

    /**
     * @param Member $member
     * @return ValidationResult|Member
     */
    public function checkNoYubiAttempts(Member $member)
    {
        $noYubiLogins = $this->checkNoYubiLogins($member);
        if ($noYubiLogins instanceof Member) {
            return $this->checkNoYubiDays($member);
        }

        return $noYubiLogins;
    }

    /**
     * Check if a member is allowed to login without a yubikey
     *
     * @param  Member $member
     * @return ValidationResult|Member
     */
    public function checkNoYubiLogins(Member $member)
    {
        $maxNoYubi = static::config()->get('MaxNoYubiLogin');
        if ($maxNoYubi > 0 && $maxNoYubi <= $member->NoYubikeyCount) {
            $validationResult = ValidationResult::create();
            $validationResult->addError(
                _t(
                    self::class . '.ERRORMAXYUBIKEY',
                    'Maximum login without yubikey exceeded'
                )
            );

            $member->registerFailedLogin();

            return $validationResult;
        }

        return $member;
    }

    /**
     * Check if the member is allowed login after so many days of not using a yubikey
     *
     * @param  Member $member
     * @return ValidationResult|Member
     */
    public function checkNoYubiDays(Member $member)
    {
        $date1 = new DateTime($member->Created);
        $date2 = new DateTime(date('Y-m-d'));

        $diff = $date2->diff($date1)->format("%a");
        $maxNoYubiDays = static::config()->get('MaxNoYubiLoginDays');

        if ($maxNoYubiDays > 0 && $diff >= $maxNoYubiDays) {
            $validationResult = ValidationResult::create();
            $validationResult->addError(
                _t(
                    self::class . '.ERRORMAXYUBIKEYDAYS',
                    'Maximum days without yubikey exceeded'
                )
            );
            $member->registerFailedLogin();

            return $validationResult;
        }

        return $member;
    }

    /**
     * @param $data
     * @param $member
     * @param ValidationResult $result
     * @return ValidationResult|Member
     */
    public function checkYubikey($data, $member, ValidationResult $result)
    {
        return $this->authenticateYubikey($data, $member, $result);
    }

    /**
     * Validate a member plus it's yubikey login. It compares the fingerprintt and after that,
     * tries to validate the Yubikey string
     *
     * @todo improve this, it's a bit overly complicated
     * @todo use the ValidationResult as e reference instead of returning
     *
     * @param  array $data
     * @param  Member $member
     * @param ValidationResult $validationResult
     * @return ValidationResult|Member
     */
    private function authenticateYubikey($data, $member, ValidationResult &$validationResult = null)
    {
        $yubiCode = QwertyConvertor::convertString($data['yubiauth']);
        $yubiFingerprint = substr($yubiCode, 0, -32);
        if (!$validationResult) {
            $validationResult = ValidationResult::create();
        }

        if ($member->Yubikey) {
            $this->validateToken($member, $yubiFingerprint, $validationResult);
            if (!$validationResult->isValid()) {
                $member->registerFailedLogin();

                return $validationResult;
            }
        }
        try {
            /** @var Response $result */
            $result = $this->service->check($yubiCode);

            // Only check if the call itself doesn't throw an error
            if ($result->success() === true) {
                $this->updateMember($member, $yubiFingerprint);

                return $member;
            }
        } catch (Exception $e) {
            $validationResult->addError($e->getMessage());

            $member->registerFailedLogin();

            return $validationResult;
        }

        $validationResult->addError(_t(self::class . '.ERROR', 'Yubikey authentication error'));
        $member->registerFailedLogin();

        return $validationResult;
    }

    /**
     * Check if the yubikey is unique and linked to the member trying to logon
     *
     * @param  Member $member
     * @param  string $yubiFingerprint
     * @param ValidationResult $validationResult
     * @return void
     */
    public function validateToken(Member $member, $yubiFingerprint, ValidationResult &$validationResult)
    {
        /** @var DataList|Member[] $yubikeyMembers */
        $yubikeyMembers = Member::get()->filter(['Yubikey' => $yubiFingerprint]);

        /** @var ValidationResult $validationResult */
        $validationResult = ValidationResult::create();

        $this->validateMemberCount($member, $yubikeyMembers, $validationResult);
        // Yubikeys have a unique fingerprint, if we find a different member with this yubikey ID, something's wrong
        $this->validateMemberID($member, $yubikeyMembers, $validationResult);

        // If the member has a yubikey ID set, compare it to the fingerprint.
        $this->validateFingerprint($member, $yubiFingerprint, $validationResult);
    }

    /**
     * @param Member $member
     * @param DataList|Member[] $yubikeyMembers
     * @param ValidationResult $validationResult
     */
    protected function validateMemberCount(
        Member $member,
        DataList $yubikeyMembers,
        ValidationResult $validationResult
    ) {
        if ($yubikeyMembers->count() > 1) {
            $validationResult->addError(
                _t(
                    self::class . '.DUPLICATE',
                    'Yubikey is duplicate, contact your administrator as soon as possible!'
                )
            );
            $member->registerFailedLogin();
        }
    }

    /**
     * @param Member $member
     * @param DataList|Member[] $yubikeyMembers
     * @param ValidationResult $validationResult
     */
    protected function validateMemberID(Member $member, DataList $yubikeyMembers, ValidationResult $validationResult)
    {
        if ((int)$yubikeyMembers->count() === 1 && (int)$yubikeyMembers->first()->ID !== (int)$member->ID) {
            $validationResult->addError(_t(self::class . '.NOMATCHID', 'Yubikey does not match found member ID'));
            $member->registerFailedLogin();
        }
    }

    /**
     * @param Member $member
     * @param $fingerPrint
     * @param ValidationResult $validationResult
     */
    protected function validateFingerprint(Member $member, $fingerPrint, ValidationResult $validationResult)
    {
        if ($member->Yubikey && strpos($fingerPrint, $member->Yubikey) !== 0) {
            $member->registerFailedLogin();
            $validationResult->addError(
                _t(
                    self::class . '.NOMATCH',
                    'Yubikey fingerprint does not match found member'
                )
            );
        }
    }

    /**
     * Update the member to forcefully enable YubiAuth
     * Also, register the Yubikey to the member.
     * Documentation:
     * https://developers.yubico.com/yubikey-val/Getting_Started_Writing_Clients.html
     *
     * @param Member $member
     * @param string $yubiString The Identifier String of the Yubikey
     * @throws ValidationException
     */
    private function updateMember($member, $yubiString)
    {
        $member->registerSuccessfulLogin();
        $member->NoYubikeyCount = 0;

        if (!$member->MFAEnabled) {
            $member->MFAEnabled = true;
        }
        if (!$member->Yubikey) {
            $member->Yubikey = $yubiString;
        }
        $member->write();
    }

    /**
     * @return Validate
     */
    public function getService()
    {
        return $this->service;
    }

    /**
     * @param Validate $service
     */
    public function setService($service)
    {
        $this->service = $service;
    }
}
