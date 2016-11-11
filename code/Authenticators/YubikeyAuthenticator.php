<?php
namespace Firesphere\YubiAuth;

use Controller;
use Form;
use Member;
use MemberAuthenticator;

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
     * @return bool|Member
     */
    public static function authenticate($data, Form $form = null)
    {
        // First, let's see if we know the member
        $member = parent::authenticate($data, $form);
        // If we know the member, and it's YubiAuth enabled, continue.
        if ($member &&
            $member instanceof Member &&
            $data['Yubikey'] !== ''
        ) {
            $data['Yubikey'] = strtolower($data['Yubikey']);
            $yubiCode = QwertyConvertor::convertString($data['Yubikey']);
            $yubiFingerprint = substr($yubiCode, 0, -32);
            // If the member has a yubikey ID set, compare it to the fingerprint.
            if($member->Yubikey && strpos($yubiFingerprint, $member->Yubikey) !== 0) {
                return false; // Yubikey id doesn't match the member.
            }
            $url = self::config()->get('AuthURL');
            $clientID = YUBIAUTH_CLIENTID;
            $apiKey = YUBIAUTH_APIKEY;
            $service = new \Yubikey\Validate($apiKey, $clientID);
            if ($url) {
                $service->setHost($url);
            }
            $result = $service->check($yubiCode);

            if ($result->success() === true) {
                self::updateMember($member, $yubiFingerprint);

                return $member;
            }
        } elseif ($member && $member instanceof Member && !$member->YubiAuthEnabled) { // We do not have to check the YubiAuth for now.
            return $member;
        }

        return false;
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

}