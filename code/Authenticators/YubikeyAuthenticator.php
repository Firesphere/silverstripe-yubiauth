<?php

/**
 * Class YubikeyAuthenticator
 *
 * Enable Yubikey Authentication.
 */
class YubikeyAuthenticator extends MemberAuthenticator
{

    /**
     * @inheritdoc
     * @param array $data
     * @param Form|null $form
     * @return bool|Member
     */
    public static function authenticate($data, Form $form = null)
    {
        // First, let's see if we know the member
        $member = parent::authenticate($data, $form);
        // If we know the member, and it's YubiAuth enabled, continue.
        if ($member && $member instanceof Member && $data['Yubikey'] !== '') {
            $url = self::config()->get('AuthURL');
            $clientID = YUBIAUTH_CLIENTID;
            $apiKey = YUBIAUTH_APIKEY;
            $service = new \Yubikey\Validate($apiKey, $clientID);
            if($url) {
                $service->setHost($url);
            }
            /** The string is Dvorak, convert it to QWERTY */
            if(strpos($data['Yubikey'], 'jjjjjj') === 0) {
                $data['Yubikey'] = self::convertDvorak($data['Yubikey']);
            }
            $result = $service->check($data['Yubikey']);

            if ($result->success() === true) {
                // If the member does not have the YubiAuth enabled, but is able to use a YubiKey, let's enable YubiAuth
                if(!$member->YubiAuthEnabled) {
                    $member->YubiAuthEnabled = true;
                    $member->write();
                }
                return $member;
            }
        } elseif($member && $member instanceof Member && !$member->YubiAuthEnabled) { // We do not have to check the YubiAuth for now.
            return $member;
        }
        self::record_login_attempt($data, $member, false);
        return false;
    }

    /**
     * @param Controller $controller
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

    private static function convertDvorak($dvorakString)
    {
        $dvorakArray = str_split($dvorakString);
        $qwerty = str_split("-=qwertyuiop[]asdfghjkl;'zxcvbnm,./_+QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?");
        $dvorak = str_split("[]',.pyfgcrl/=aoeuidhtns-;qjkxbmwvz{}\"<>PYFGCRL?+AOEUIDHTNS_:QJKXBMWVZ");
        $return = '';
        foreach($dvorakArray as $item) {
            $return .= $qwerty[array_search($item, $dvorak, true)];
        }
        return $return;
    }

}