<?php
use Yubikey\Response;
use Yubikey\ResponseCollection;
use Yubikey\Validate;


class MockYubiValidate extends Validate
{

    public function check($otp, $multi = false, $fail = false)
    {
        $nonce = $this->generateNonce();
        $result = new Response(array(
            'h' => '',
            'otp' => 'ccccccfinfgrtjhdeitnirlnggbicvnnthethdljlcvl',
            'status' => $fail ? 'BAD_OTP' : 'OK',
            'nonce' => $nonce,
            'inputNonce' => $nonce,
            'inputOtp' => 'ccccccfinfgrtjhdeitnirlnggbicvnnthethdljlcvl',
            'host' => 'api.yubico.com',
            'sl' => 25,
            'timestamp' => time()
        ));
        return new ResponseCollection(array($result));
    }

    public function success()
    {

    }
}