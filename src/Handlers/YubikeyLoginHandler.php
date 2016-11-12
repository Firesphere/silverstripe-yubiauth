<?php

namespace Firesphere\YubiAuth;

use SilverStripe\Control\Session;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\LoginHandler as MemberLoginHandler;
use SilverStripe\Security\Security;

class YubikeyLoginHandler extends MemberLoginHandler
{

    private static $url_handlers = [
        'yubikey-authentication' => 'secondFactor'
    ];

    private static $allowed_actions = [
        'LoginForm',
        'dologin',
        'secondFactor',
        'yubikeyForm'
    ];

    /**
     * Return the MemberLoginForm form
     */
    public function loginForm()
    {
        return YubikeyLoginForm::create(
            $this,
            get_class($this->authenticator),
            'LoginForm'
        );
    }

    public function doLogin($data, $formHandler)
    {
        if ($member = $this->checkLogin($data, $message)) {
            Session::set('YubikeyLoginHandler.MemberID', $member->ID);
            Session::set('YubikeyLoginHandler.Data', $data);
            Session::set('YubikeyLoginHandler.BackURL', $data['BackURL']);

            return $this->redirect($this->link('yubikey-authentication'));
        }
        $this->redirectBack();

    }

    public function secondFactor()
    {
        return ['Form' => $this->yubikeyForm()];
    }

    public function yubikeyForm()
    {
        return YubikeyForm::create($this, 'yubikeyForm');
    }

    public function validateYubikey($data)
    {
        $message = false;
        $memberData = Session::get('YubikeyLoginHandler.Data');
        $this->request['BackURL'] = !empty($memberData['BackURL']) ? $memberData['BackURL'] : '';
        $member = $this->authenticator->validateYubikey($data, $message);
        if ($member instanceof Member) {
            $memberData = Session::get('YubikeyLoginHandler.Data');
            $this->performLogin($member, $memberData, $this->getRequest());
            Security::setCurrentUser($member);
            Session::clear('YubikeyLoginHandler');

            return $this->redirectAfterSuccessfulLogin();
        }

        return $this->redirect($this->link());
    }
}