<?php

namespace Firesphere\YubiAuth;

use Firesphere\BootstrapMFA\MFALoginHandler;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class YubikeyLoginHandler extends MFALoginHandler
{

    private static $url_handlers = [
        'verify' => 'secondFactor'
    ];

    private static $allowed_actions = [
        'LoginForm',
        'dologin',
        'secondFactor',
        'MFAForm'
    ];

    /**
     * Return the MemberLoginForm form
     */
    public function LoginForm()
    {
        return YubikeyLoginForm::create(
            $this,
            get_class($this->authenticator),
            'LoginForm'
        );
    }

    public function MFAForm()
    {
        return YubikeyForm::create($this, __FUNCTION__);
    }

    /**
     * @param array $data
     * @param YubikeyForm $form
     * @param HTTPRequest $request
     * @return \SilverStripe\Control\HTTPResponse
     */
    public function validateYubikey($data, $form, $request)
    {
        $session = $request->getSession();
        $message = false;
        $memberData = $session->get('MFALogin.Data');
        $this->request['BackURL'] = !empty($memberData['BackURL']) ? $memberData['BackURL'] : '';
        $member = $this->authenticator->validateYubikey($data, $request, $message);
        $memberData = $session->get('MFALogin.Data');
        if ($member instanceof Member) {
            $this->performLogin($member, $memberData, $this->getRequest());
            Security::setCurrentUser($member);
            $session->clear('YubikeyLoginHandler');

            return $this->redirectAfterSuccessfulLogin();
        } elseif (isset($data['yubiauth'])) {
            $data['token'] = $data['yubiauth'];
            if ($member = parent::validate($data, $form, $request)) {
                $this->performLogin($member, $memberData, $request);
                Security::setCurrentUser($member);

                return $this->redirectAfterSuccessfulLogin();
            }
        }

        return $this->redirect($this->link());
    }
}
