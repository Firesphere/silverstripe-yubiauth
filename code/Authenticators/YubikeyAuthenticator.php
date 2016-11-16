<?php
namespace Firesphere\YubiAuth;

use Config;
use Controller;
use DateTime;
use Form;
use Injector;
use Member;
use MemberAuthenticator;
use ValidationResult;
use Yubikey\Response;
use Yubikey\Validate;

/**
 * Class YubikeyAuthenticator
 *
 * Enable Yubikey Authentication for SilverStripe CMS and member-protected pages.
 */
class YubikeyAuthenticator extends MemberAuthenticator
{
    /**
     * @var null|Form
     */
    protected static $form;

    /**
     * @var Validate
     */
    protected static $yubiService;

    /**
     * @inheritdoc
     *
     * @param array $data
     * @param Form|null $form
     *
     * @return null|Member
     */
    public static function authenticate($data, Form $form = null)
    {
        self::$form = $form;
        $currentLoginRecording = Config::inst()->get('Security', 'login_recording');
        Config::inst()->update('Security', 'login_recording', false); // Disable login_recording for this auth.
        // First, let's see if we know the member
        $member = parent::authenticate($data, $form);
        Config::inst()->update('Security', 'login_recording', $currentLoginRecording); // Reset login_recording
        // Continue if we have a valid member
        if ($member && $member instanceof Member) {
            // If we know the member, and it's YubiAuth enabled, continue.
            if ($member->YubiAuthEnabled || $data['Yubikey'] !== '') {
                /** @var Validate $service */
                self::$yubiService = Injector::inst()->createWithArgs('Yubikey\Validate',
                    array(YUBIAUTH_APIKEY, YUBIAUTH_CLIENTID));
                if ($url = self::config()->get('AuthURL')) {
                    $service->setHost($url);
                }

                return self::authenticate_yubikey($data, $member);
            } elseif (!$member->YubiAuthEnabled) { // We do not have to check the YubiAuth for now.
                return self::authenticate_noyubikey($member);
            }
            $member->registerFailedLogin();
        }
        self::updateForm();

        return null;
    }

    /**
     * @param Controller $controller
     *
     * @return Form
     */
    public static function get_login_form(Controller $controller)
    {
        return YubikeyLoginForm::create($controller, 'LoginForm');
    }

    /**
     * Name of this authenticator
     *
     * @return string
     */
    public static function get_name()
    {
        return _t('YubikeyAuthenticator.TITLE', 'Yubikey login');
    }

    /**
     * Update the member to forcefully enable YubiAuth
     * Also, register the Yubikey to the member.
     * Documentation:
     * https://developers.yubico.com/yubikey-val/Getting_Started_Writing_Clients.html
     *
     * @param Member $member
     * @param string $yubiString The Identifier String of the Yubikey
     */
    private static function updateMember($member, $yubiString)
    {
        $member->registerSuccessfulLogin();
        $member->NoYubikeyCount = 0;

        if (!$member->YubiAuthEnabled) {
            $member->YubiAuthEnabled = true;
        }
        if (!$member->Yubikey) {
            $member->Yubikey = $yubiString;
        }
        $member->write();
    }

    /**
     * @param null|ValidationResult $validation
     */
    private static function updateForm($validation = null)
    {
        $form = self::$form;
        if ($form) {
            if ($validation === null) {
                // Default validation error.
                $validation = ValidationResult::create(false,
                    _t('YubikeyAuthenticator.ERRORYUBIKEY', 'Yubikey authentication error'));
            }
            $form->sessionMessage($validation->message(), 'bad');
        }

    }

    /**
     * Validate a member plus it's yubikey login. It compares the fingerprintt and after that, tries to validate the Yubikey string
     * @param array $data
     * @param Member $member
     * @return null|Member
     */
    private static function authenticate_yubikey($data, $member)
    {
        $data['Yubikey'] = strtolower($data['Yubikey']);
        $yubiCode = QwertyConvertor::convertString($data['Yubikey']);
        $yubiFingerprint = substr($yubiCode, 0, -32);
        if (!self::validateYubikey($member, $yubiFingerprint)) {
            return null;
        }
        /** @var Response $result */
        $result = self::$yubiService->check($yubiCode);

        if ($result->success() === true) {
            self::updateMember($member, $yubiFingerprint);

            return $member;
        } else {
            $validationMessage = ValidationResult::create(false,
                _t('YubikeyAuthenticator.ERROR', 'Yubikey authentication error'));
            self::updateForm($validationMessage);
            $member->registerFailedLogin();

            return null;
        }
    }

    /**
     * Check if the yubikey is unique and linked to the member trying to logon
     *
     * @param Member $member
     * @param string $yubiFingerprint
     * @return boolean
     */
    private static function validateYubikey($member, $yubiFingerprint)
    {
        $yubikeyMember = Member::get()->filter(array('Yubikey' => $yubiFingerprint))->first();
        // Yubikeys have a unique fingerprint, if we find a different member with this yubikey ID, something's wrong
        if ($yubikeyMember && $yubikeyMember->ID !== $member->ID) {
            $validationMessage = ValidationResult::create(false,
                _t('YubikeyAuthenticator.DUPLICATE', 'Yubikey is duplicate'));
            self::updateForm($validationMessage);
            $member->registerFailedLogin();

            return false;
        }
        // If the member has a yubikey ID set, compare it to the fingerprint.
        if ($member->Yubikey && strpos($yubiFingerprint, $member->Yubikey) !== 0) {
            self::updateForm();
            $member->registerFailedLogin();

            return false; // Yubikey id doesn't match the member.
        }

        return true;
    }


    /**
     * Handle login if the user did not enter a Yubikey string.
     * Will break out and return NULL if the member should use their Yubikey
     *
     * @param Member $member
     * @return null|Member
     */
    private static function authenticate_noyubikey($member)
    {
        ++$member->NoYubikeyCount;
        $member->write();
        if (!self::checkNoYubiLogins($member) || !self::checkNoYubiDays($member)) {
            return null;
        }

        return $member;
    }

    /**
     * Check if a member is allowed to login without a yubikey
     *
     * @param Member $member
     * @return bool|Member
     */
    private static function checkNoYubiLogins($member)
    {
        $maxNoYubi = self::config()->get('MaxNoYubiLogin');
        if ($maxNoYubi > 0 && $maxNoYubi <= $member->NoYubikeyCount) {
            $validationError = ValidationResult::create(false,
                _t('YubikeyAuthenticator.ERRORMAXYUBIKEY', 'Maximum login without yubikey exceeded'));
            self::updateForm($validationError);
            $member->registerFailedLogin();

            return false;
        }

        return $member;
    }

    /**
     * Check if the member is allowed login after so many days of not using a yubikey
     *
     * @param Member $member
     * @return bool|Member
     */
    private static function checkNoYubiDays($member)
    {

        $date1 = new DateTime($member->Created);
        $date2 = new DateTime(date('Y-m-d'));

        $diff = $date2->diff($date1)->format("%a");
        $maxNoYubiDays = self::config()->get('MaxNoYubiLoginDays');

        if ($maxNoYubiDays > 0 && $diff >= $maxNoYubiDays) {
            $validationError = ValidationResult::create(false,
                _t('YubikeyAuthenticator.ERRORMAXYUBIKEYDAYS', 'Maximum days without yubikey exceeded'));
            self::updateForm($validationError);
            $member->registerFailedLogin();

            return false;
        }

        return $member;
    }
}