<?php

namespace Firesphere\YubiAuth\Handlers;

use Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use Firesphere\BootstrapMFA\Handlers\BootstrapMFALoginHandler;
use Firesphere\YubiAuth\Forms\YubikeyForm;
use Firesphere\YubiAuth\Forms\YubikeyLoginForm;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Forms\Form;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\LoginForm;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberLoginForm;
use SilverStripe\Security\PasswordEncryptor_NotFoundException;
use SilverStripe\Security\Security;

/**
 * Class YubikeyLoginHandler
 */
class YubikeyLoginHandler extends BootstrapMFALoginHandler
{
    /**
     * @var array
     */
    private static $url_handlers = [
        'yubikey-authentication' => 'secondFactor',
        'verify'                 => 'secondFactor'
    ];

    /**
     * @var array
     */
    private static $allowed_actions = [
        'LoginForm',
        'dologin',
        'secondFactor',
        'yubikeyForm',
        'verify'
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

    /**
     * @param array $data
     * @param LoginForm|MemberLoginForm $form
     * @param HTTPRequest $request
     * @return HTTPResponse
     */
    public function doLogin($data, MemberLoginForm $form, HTTPRequest $request)
    {
        if ($member = $this->checkLogin($data, $request, $result)) {
            $session = $request->getSession();
            $session->set(BootstrapMFAAuthenticator::SESSION_KEY . '.MemberID', $member->ID);
            $session->set(BootstrapMFAAuthenticator::SESSION_KEY . '.Data', $data);
            if (!empty($data['BackURL'])) {
                $session->set(BootstrapMFAAuthenticator::SESSION_KEY . '.BackURL', $data['BackURL']);
            }

            return $this->redirect($this->link('yubikey-authentication'));
        }

        return $this->redirectBack();
    }

    /**
     * @return array|Form[]
     */
    public function secondFactor()
    {
        return ['Form' => $this->yubikeyForm()];
    }

    /**
     * @return YubikeyForm
     */
    public function yubikeyForm()
    {
        return YubikeyForm::create($this, 'yubikeyForm');
    }

    /**
     * @return YubikeyForm
     */
    public function MFAForm()
    {
        return $this->yubikeyForm();
    }

    /**
     * @param array $data
     * @param YubikeyForm $form
     * @param HTTPRequest $request
     * @return HTTPResponse
     * @throws ValidationException
     * @throws PasswordEncryptor_NotFoundException
     */
    public function validateToken($data, $form, $request)
    {
        $session = $request->getSession();

        $memberData = $session->get(BootstrapMFAAuthenticator::SESSION_KEY . '.Data');
        $this->request['BackURL'] = !empty($memberData['BackURL']) ? $memberData['BackURL'] : '';

        $member = $this->authenticator->validateToken($data, $request, $validationResult);

        if (!$member instanceof Member) {
            $data['token'] = $data['yubiauth'];
            $member = parent::validate($data, $form, $request, $validationResult);
        }

        if ($member instanceof Member) {
            $memberData = $session->get(BootstrapMFAAuthenticator::SESSION_KEY . '.Data');
            $this->performLogin($member, $memberData, $request);
            Security::setCurrentUser($member);
            $session->clear(BootstrapMFAAuthenticator::SESSION_KEY);

            return $this->redirectAfterSuccessfulLogin();
        }

        $form->setSessionValidationResult($validationResult);

        return $this->redirect($this->link());
    }
}
