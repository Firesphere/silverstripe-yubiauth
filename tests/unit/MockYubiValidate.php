<?php

namespace Firesphere\YubiAuth\Tests;

use Yubikey\Response;
use Yubikey\ResponseCollection;
use Yubikey\Validate;


class MockYubiValidate extends Validate
{

    public function check($otp, $multi = false)
    {
        $nonce = $this->generateNonce();
        $result = new Response(
            [
            'h' => '',
            'otp' => $otp,
            'status' => 'OK',
            'nonce' => $nonce,
            'inputNonce' => $nonce,
            'inputOtp' => $otp,
            'host' => 'api.yubico.com',
            'sl' => 25,
            'timestamp' => time()
            ]
        );
        return new ResponseCollection([$result]);
    }

}
