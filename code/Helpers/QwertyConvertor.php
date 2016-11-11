<?php
namespace Firesphere\YubiAuth;

/**
 * @description Helper Class to convert different keyboard layouts to Qwerty before authenticating
 */
class QwertyConvertor
{
    /**
     * Detect different keyboard layouts and return the converted string.
     * @param string $yubiString
     *
     * @return string
     */
    public static function convertString($yubiString)
    {
        /** The string is Dvorak, convert it to QWERTY */
        if (strpos($yubiString, 'jjjjjj') === 0) {
            return self::convertDvorak($yubiString);
        }
        return $yubiString;
    }

    /**
     * @param string $dvorakString
     *
     * @return string
     */
    public static function convertDvorak($dvorakString)
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