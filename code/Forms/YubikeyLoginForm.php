<?php

class YubikeyLoginForm extends MemberLoginForm
{

    protected $authenticator_class = 'YubikeyAuthenticator';

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
        if ($checkCurrentUser && Member::currentUser() && Member::logged_in_session_exists()) {
            parent::__construct($controller, $name, $fields, $actions);
        } else {
            $label = Injector::inst()->get('Member')->fieldLabel(Member::config()->unique_identifier_field);
            if (!$fields) {
                $fields = FieldList::create(
                    $emailField = TextField::create("Email", $label, null, null, $this),
                    HiddenField::create("AuthenticationMethod", null, $this->authenticator_class, $this),
                    //Regardless of what the unique identifer field is (usually 'Email'), it will be held in the 'Email' value, below:
                    PasswordField::create("Password", _t('Member.PASSWORD', 'Password')),
                    PasswordField::create("Yubikey", _t('YubikeyAuthenticater.FORMFIELDNAME', 'Yubikey Authentication'))
                );
            }
            if (!$actions) {
                $actions = FieldList::create(
                    FormAction::create('dologin', _t('Member.BUTTONLOGIN', 'Log in'))
                );
            }
        }

        parent::__construct($controller, $name, $fields, $actions);


    }

}
