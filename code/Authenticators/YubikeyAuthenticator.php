<?php
namespace Firesphere\YubiAuth;

use Config;
use Controller;
use DateTime;
use Form;
use Member;
use MemberAuthenticator;
use ValidationResult;

/**
 * Class YubikeyAuthenticator
 *
 * Enable Yubikey Authentication.
 */
class YubikeyAuthenticator extends MemberAuthenticator
{

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
        Config::inst()->update('Security', 'login_recording', false); // Disable login_recording for this auth.
        // First, let's see if we know the member
        $member = parent::authenticate($data, $form);
        Config::inst()->update('Security', 'login_recording', true);
        $validationError = ValidationResult::create(false,
            _t('YubikeyAuthenticator.ERRORYUBIKEY', 'Yubikey authentication error'));
        if ($member && $member instanceof Member) {
            // If we know the member, and it's YubiAuth enabled, continue.
            if ($member &&
                ($member->YubiAuthEnabled || $data['Yubikey'] !== '')
            ) {
                $data['Yubikey'] = strtolower($data['Yubikey']);
                $yubiCode = QwertyConvertor::convertString($data['Yubikey']);
                $yubiFingerprint = substr($yubiCode, 0, -32);
                // If the member has a yubikey ID set, compare it to the fingerprint.
                if ($member->Yubikey && strpos($yubiFingerprint, $member->Yubikey) !== 0) {
                    self::updateForm($validationError, $form);

                    return null; // Yubikey id doesn't match the member.
                }
                $clientID = YUBIAUTH_CLIENTID;
                $apiKey = YUBIAUTH_APIKEY;
                $service = new \Yubikey\Validate($apiKey, $clientID);
                if ($url = self::config()->get('AuthURL')) {
                    $service->setHost($url);
                }
                $result = $service->check($yubiCode);

                if ($result->success() === true) {
                    self::updateMember($member, $yubiFingerprint);
                    if ($member) {
                        $member->registerSuccessfulLogin();
                        $member->MaxNoYubiLogins = 0;
                        $member->write();
                    }

                    return $member;
                } else {
                    self::updateForm($validationError, $form);

                    return null;
                }
            } elseif (!$member->YubiAuthEnabled) { // We do not have to check the YubiAuth for now.
                $member->NoYubikeyCount += 1;
                $member->write();
                $maxNoYubi = Config::inst()->get('YubikeyAuthenticator', 'MaxNoYubiLogin');
                if ($maxNoYubi > 0 && $maxNoYubi <= $member->NoYubikeyCount) {
                    $validationError = ValidationResult::create(false,
                        _t('YubikeyAuthenticator.ERRORMAXYUBIKEY', 'Maximum login without yubikey exceeded'));
                    self::updateForm($validationError, $form);
                    $member->registerFailedLogin();

                    return null;
                }
                $date1 = new DateTime($member->Created);
                $date2 = new DateTime(date('Y-m-d'));

                $diff = $date2->diff($date1)->format("%a");
                $maxNoYubiDays = Config::inst()->get('YubikeyAuthenticator', 'MaxNoYubiLoginDays');

                if ($maxNoYubiDays > 0 && $diff >= $maxNoYubiDays) {
                    $validationError = ValidationResult::create(false,
                        _t('YubikeyAuthenticator.ERRORMAXYUBIKEYDAYS', 'Maximum days without yubikey exceeded'));
                    self::updateForm($validationError, $form);
                    $member->registerFailedLogin();

                    return null;

                }

                return $member;
            }
        }
        if ($member) {
            $member->registerFailedLogin();
        }
        self::updateForm($validationError, $form);

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
     * @param string $yubiString
     */
    private static function updateMember($member, $yubiString)
    {
        if (!$member->YubiAuthEnabled) {
            $member->YubiAuthEnabled = true;
        }
        if (!$member->Yubikey) {
            $member->Yubikey = $yubiString;
        }
        $member->write();
    }

    /**
     * @param ValidationResult $validation
     * @param null|Form $form
     */
    private static function updateForm($validation, $form)
    {
        if ($form) {
            $form->sessionMessage($validation->message(), 'bad');
        }

    }

}