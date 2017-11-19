<?php

namespace Firesphere\YubiAuth;


use DateTime;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

/**
 * Class YubiAuthProvider
 *
 * @package Firesphere\YubiAuth
 */
abstract class YubiAuthProvider
{
    use Configurable;

    /**
     * @param Member $member
     * @return ValidationResult|Member
     */
    public static function checkNoYubiAttempts(Member $member)
    {
        $noYubiLogins = self::checkNoYubiLogins($member);
        if ($noYubiLogins instanceof Member) {
            return self::checkNoYubiDays($member);
        }

        return $noYubiLogins;
    }

    /**
     * Check if a member is allowed to login without a yubikey
     *
     * @param  Member $member
     * @return ValidationResult|Member
     */
    public static function checkNoYubiLogins(Member $member)
    {
        $maxNoYubi = self::config()->get('MaxNoYubiLogin');
        if ($maxNoYubi > 0 && $maxNoYubi <= $member->NoYubikeyCount) {
            $validationResult = ValidationResult::create();
            $validationResult->addError(
                _t(
                    'YubikeyAuthenticator.ERRORMAXYUBIKEY',
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
    public static function checkNoYubiDays(Member $member)
    {

        $date1 = new DateTime($member->Created);
        $date2 = new DateTime(date('Y-m-d'));

        $diff = $date2->diff($date1)->format("%a");
        $maxNoYubiDays = self::config()->get('MaxNoYubiLoginDays');

        if ($maxNoYubiDays > 0 && $diff >= $maxNoYubiDays) {
            $validationResult = ValidationResult::create();
            $validationResult->addError(
                _t(
                    'YubikeyAuthenticator.ERRORMAXYUBIKEYDAYS',
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
     * @return ValidationResult|bool
     */
    public static function validateYubikey(Member $member, $yubiFingerprint)
    {
        $yubikeyMembers = Member::get()->filter(['Yubikey' => $yubiFingerprint]);
        // Yubikeys have a unique fingerprint, if we find a different member with this yubikey ID, something's wrong
        if ($yubikeyMembers->count() > 1) {
            $validationResult = ValidationResult::create();
            $validationResult->addError(
                _t(
                    'YubikeyAuthenticator.DUPLICATE',
                    'Yubikey is duplicate, contact your administrator as soon as possible!'
                )
            );
            $member->registerFailedLogin();

            return $validationResult;
        }
        if (!$yubikeyMembers->count() || $yubikeyMembers->first()->ID !== $member->ID) {
            $validationResult = ValidationResult::create();
            $validationResult->addError(_t('YubikeyAuthenticator.NOMATCH', 'Yubikey does not match found member'));
            $member->registerFailedLogin();

            return $validationResult;
        }
        // If the member has a yubikey ID set, compare it to the fingerprint.
        if ($member->Yubikey && strpos($yubiFingerprint, $member->Yubikey) !== 0) {
            $member->registerFailedLogin();
            $validationResult = ValidationResult::create();
            $validationResult->addError(
                _t(
                    'YubikeyAuthenticator.NOMATCH',
                    'Yubikey fingerprint does not match found member'
                )
            );

            return $validationResult; // Yubikey id doesn't match the member.
        }

        return true;
    }
}
