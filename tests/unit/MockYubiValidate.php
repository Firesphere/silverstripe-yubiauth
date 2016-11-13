<?php
use Yubikey\Response;
use Yubikey\ResponseCollection;
use Yubikey\Validate;


class MockYubiValidate extends Validate
{

    private $fail;

    public function __construct($apiKey, $clientId, array $hosts = array(), $fail = false)
    {
        $this->fail = $fail;
        parent::__construct($apiKey, $clientId, $hosts);
    }

    public function check($otp, $multi = false)
    {
        $nonce = $this->generateNonce();
        $result = new Response(array(
            'h' => '',
            'otp' => $otp,
            'status' => $this->fail ? 'REPLAYED_OTP' : 'OK',
            'nonce' => $nonce,
            'inputNonce' => $nonce,
            'inputOtp' => $otp,
            'host' => 'api.yubico.com',
            'sl' => 25,
            'timestamp' => time()
        ));
        return new ResponseCollection(array($result));
    }

}