<?php

namespace Firesphere\YubiAuth\Providers;

use DateTime;
use Firesphere\BootstrapMFA\Providers\BootstrapMFAProvider;
use Firesphere\BootstrapMFA\Providers\MFAProvider;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

/**
 * Class YubikeyAuthProvider
 *
 * @package Firesphere\YubiAuth
 */
class YubikeyAuthProvider extends BootstrapMFAProvider implements MFAProvider
{
    use Configurable;

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
     * Check if the yubikey is unique and linked to the member trying to logon
     *
     * @param  Member $member
     * @param  string $yubiFingerprint
     * @return ValidationResult
     */
    public function validateToken(Member $member, $yubiFingerprint)
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


        return $validationResult;
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
}
