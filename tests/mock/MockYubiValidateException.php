<?php

namespace Firesphere\YubiAuth\Tests;

use Exception;
use Yubikey\Validate;

/**
 * Class MockYubiValidateException
 * @package Firesphere\YubiAuth\Tests
 */
class MockYubiValidateException extends Validate
{
    /**
     * @param string $otp
     * @param bool $multi
     * @return void|\Yubikey\Response
     * @throws Exception
     */
    public function check($otp, $multi = false)
    {
        throw new Exception('I do not like this', 1);
    }
}
