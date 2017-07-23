<?php

namespace Firesphere\YubiAuth;

/**
 * @description Helper Class to convert different keyboard layouts to Qwerty before authenticating
 */
class QwertyConvertor
{
    /**
     * @var string Dvorak layout
     */
    protected static $dvorak = "[]',.pyfgcrl/=aoeuidhtns-;qjkxbmwvz{}\"<>PYFGCRL?+AOEUIDHTNS_:QJKXBMWVZ";

    /**
     * @var string Qwerty layout
     */
    protected static $qwerty = "-=qwertyuiop[]asdfghjkl;'zxcvbnm,./_+QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?";

    /**
     * This might be tricky to detect, as the initial position of C seems to be the same
     *
     * @var string Azerty layout conversion
     */
    protected static $azerty = ")-azertyuiop^\$qsdfghjklmùwxcvbn,;:=°_AZERTYUIOP¨*QSDFGHJKLM%WXCVBN?./+";

    /**
     * Detect different keyboard layouts and return the converted string.
     * A Yubi-string alsways starts with `cccccc`. If it's different, we have a different layout.
     * Dvorak is easy to detect. Azerty on the other hand, might be tricky.
     * Other conversion additions welcome.
     *
     * @param string $yubiString
     *
     * @return string
     */
    public static function convertString($yubiString)
    {
        $yubiString = strtolower($yubiString);
        /* The string is Dvorak, convert it to QWERTY */
        if (strpos($yubiString, 'jjjjjj') === 0) {
            return self::convertToQwerty($yubiString, 'dvorak');
        }

        return $yubiString;
    }

    /**
     * @param string $originalString
     * @param string $from           Origin we have to convert from
     *
     * @return string
     */
    public static function convertToQwerty($originalString, $from)
    {
        $originalArray = str_split($originalString);
        $qwerty = str_split(self::$qwerty);
        $from = str_split(self::$$from);
        $return = '';
        foreach ($originalArray as $item) {
            $return .= $qwerty[array_search($item, $from, true)];
        }

        return $return;
    }

}
