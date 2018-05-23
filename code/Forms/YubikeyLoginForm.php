<?php

namespace Firesphere\YubiAuth;

use Exception;
use Form;
use Injector;
use Member;
use MFAAuthenticator;
use MFAForm;
use MFALoginForm;
use Session;
use SS_HTTPRequest;

class YubikeyLoginForm extends MFALoginForm
{
    protected $authenticator_class = 'Firesphere\\YubiAuth\\YubikeyAuthenticator';

    /**
     * @var array
     */
    private static $allowed_actions = array(
        'MFAForm',
    );

    /**
     * @inheritdoc
     */
    public function __construct(
        $controller,
        $name,
        $fields = null,
        $actions = null,
        $checkCurrentUser = true
    ) {
        parent::__construct($controller, $name, $fields, $actions, $checkCurrentUser);
    }

    /**
     * Requires to call `doChallenge` as it's FormAction
     * This action should be implemented on the login form used
     * @return MFAForm
     */
    public function MFAForm()
    {
        return YubikeyForm::create($this, __FUNCTION__);
    }


    /**
     * @param array $data
     * @param Form $form
     * @param SS_HTTPRequest $request
     * @throws Exception
     */
    public function doChallenge($data, $form, $request)
    {
        $memberID = Session::get(MFAAuthenticator::SESSION_KEY . '.MemberID');
        /** @var Member $member */
        $member = Member::get()->byID($memberID);
        /** @var YubikeyAuthenticator $authenticator */
        $authenticator = Injector::inst()->get(YubikeyAuthenticator::class);
        $authenticator->setMember($member);
        $result = $authenticator->verifyToken($data['Token']);
        if ($result instanceof Member) {
            $loginData = Session::get(MFAAuthenticator::SESSION_KEY . '.loginData');
            $member->logIn(isset($loginData['Remember']));
            $this->logInUserAndRedirect($loginData);
        } else {
            $this->setMessage('2 Factor authentication failed', 'bad');
            $this->controller->redirect('/Security/Login');
        }
    }
}
