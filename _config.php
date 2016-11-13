<?php

Authenticator::register_authenticator('Firesphere\\YubiAuth\\YubikeyAuthenticator');

if(!defined('YUBIAUTH_CLIENTID')) {
    throw new LogicException('YUBIAUTH_CLIENTID Must be enabled to use YubiAuth');
}
if(!defined('YUBIAUTH_APIKEY')) {
    throw new LogicException('YUBIAUTH_APIKEY Must be enabled to use YubiAuth');
}