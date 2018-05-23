<?php

namespace Firesphere\YubiAuth;

use Config;
use DateTime;
use Injector;
use Member;
use MFABackupCodeProvider;
use MFAProvider;
use ValidationResult;
use Yubikey\Response;
use Yubikey\Validate;

/**
 * Class YubiAuthProvider
 * @package Firesphere\YubiAuth
 */
class YubikeyProvider extends MFABackupCodeProvider implements MFAProvider
{

    /**
     * @var Validate
     */
    protected $yubiService;

    /**
     * @param string $token
     * @param ValidationResult $result
     * @return bool|Member
     * @throws \Exception
     */
    public function verifyToken($token, ValidationResult $result)
    {
        /** @var Validate $service */
        $this->yubiService = Injector::inst()->createWithArgs(
            Validate::class,
            array(YUBIAUTH_APIKEY, YUBIAUTH_CLIENTID)
        );
        if ($url = Config::inst()->get(static::class, 'AuthURL')) {
            $this->yubiService->setHost($url);
        }

        return $this->authenticateYubikey($token, $result);
    }


    /**
     * Validate a member plus it's yubikey login. It compares the fingerprint and after that,
     * tries to validate the Yubikey string
     * @param $token
     * @param $result
     * @return Member|ValidationResult|Response
     * @throws \Exception
     */
    protected function authenticateYubikey($token, $result = null)
    {
        if (!$result) {
            $result = Injector::inst()->get(ValidationResult::class);
        }
        $yubiCode = QwertyConvertor::convertString($token);
        $yubiFingerprint = substr($yubiCode, 0, -32);
        $member = $this->getMember();

        $success = $this->validateYubikey($yubiFingerprint, $result);
        if (!$success) {
            return parent::verifyToken($token, $result);
        }
        /** @var Response $response */
        $response = $this->yubiService->check($yubiCode);

        if ($response->success() === true) {
            $this->updateMember($member, $yubiFingerprint);

            return $member;
        }
        $result->error(
            _t(__CLASS__ . '.ERROR', 'Yubikey authentication error'),
            2
        );

        $member->registerFailedLogin();

        return $result;
    }

    /**
     * Check if the yubikey is unique and linked to the member trying to logon
     *
     * @param string $yubiFingerprint
     * @return bool
     */
    private function validateYubikey($yubiFingerprint, &$result)
    {
        $member = $this->getMember();
        $yubikeyMember = Member::get()->filter(['Yubikey' => $yubiFingerprint]);
        // Yubikeys have a unique fingerprint, if we find a different member with this yubikey ID, something's wrong
        if ((int)$yubikeyMember->count() === 1 && $yubikeyMember->first()->ID !== $member->ID) {
            $result->error(
                _t(__CLASS__ . '.DUPLICATE', 'Yubikey is duplicate'),
                1
            );
            $member->registerFailedLogin();

            return false;
        }
        // If the member has a yubikey ID set, compare it to the fingerprint.
        if ($member->Yubikey && strpos($yubiFingerprint, $member->Yubikey) !== 0) {
            $member->registerFailedLogin();

            return false; // Yubikey id doesn't match the member.
        }

        return true;
    }

    /**
     * Update the member to forcefully enable YubiAuth
     * Also, register the Yubikey to the member.
     * Documentation:
     * https://developers.yubico.com/yubikey-val/Getting_Started_Writing_Clients.html
     *
     * @param Member $member
     * @param string $yubiString The Identifier String of the Yubikey
     * @throws \ValidationException
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
     * Handle login if the user did not enter a Yubikey string.
     * Will break out and return NULL if the member should use their Yubikey
     *
     * @param Member $member
     * @return Member|ValidationResult
     * @throws \ValidationException
     */
    public function verifyNoYubikey($member)
    {
        $result = ValidationResult::create();
        ++$member->NoYubikeyCount;
        $member->write();
        if (!$this->checkNoYubiLogins($member, $result) || !$this->checkNoYubiDays($member, $result)) {
            return $result;
        }

        return $member;
    }

    /**
     * Check if a member is allowed to login without a yubikey
     *
     * @param Member $member
     * @param ValidationResult $result
     * @return bool|Member
     */
    private function checkNoYubiLogins($member, &$result)
    {
        $maxNoYubi = $this->config()->get('MaxNoYubiLogin');
        if ($maxNoYubi > 0 && $maxNoYubi <= $member->NoYubikeyCount) {
            $result = ValidationResult::create(
                false,
                _t(__CLASS__ . '.ERRORMAXYUBIKEY', 'Maximum login without yubikey exceeded')
            );
            $member->registerFailedLogin();

            return false;
        }

        return true;
    }

    /**
     * Check if the member is allowed login after so many days of not using a yubikey
     *
     * @param Member $member
     * @return bool|Member
     */
    private function checkNoYubiDays($member, &$result)
    {
        $date1 = new DateTime($member->Created);
        $date2 = new DateTime(date('Y-m-d'));

        $diff = $date2->diff($date1)->format("%a");
        $maxNoYubiDays = $this->config()->get('MaxNoYubiLoginDays');

        if ($maxNoYubiDays > 0 && $diff >= $maxNoYubiDays) {
            $result = ValidationResult::create(
                false,
                _t(__CLASS__ . '.ERRORMAXYUBIKEYDAYS', 'Maximum days without yubikey exceeded')
            );
            $member->registerFailedLogin();

            return false;
        }

        return true;
    }
}