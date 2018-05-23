<?php

namespace Firesphere\YubiAuth;

use Config;
use Controller;
use Form;
use Injector;
use Member;
use MFAAuthenticator;
use ValidationResult;
use Yubikey\Validate;

/**
 * Class YubikeyAuthenticator
 *
 * Enable Yubikey Authentication for SilverStripe CMS and member-protected pages.
 */
class YubikeyAuthenticator extends MFAAuthenticator
{
    /**
     * @var Member
     */
    protected $member;
    /**
     * @var null|Form
     */
    protected $form;
    /**
     * @var YubikeyProvider
     */
    protected $provider;
    /**
     * @var Validate
     */
    protected $yubiService;

    public function __construct()
    {
        $this->provider = Injector::inst()->get(YubikeyProvider::class);
        parent::__construct();
    }

    /**
     * @param Controller $controller
     *
     * @return Form
     */
    public static function get_login_form(Controller $controller)
    {
        return YubikeyLoginForm::create($controller, 'LoginForm');
    }

    /**
     * Name of this authenticator
     *
     * @return string
     */
    public static function get_name()
    {
        return _t('YubikeyAuthenticator.TITLE', 'Yubikey login');
    }

    /**
     * @inheritdoc
     *
     * @param array $data
     * @param Form|null $form
     *
     * @return null|Member
     * @throws \Exception
     */
    public function verifyToken($token)
    {
        $result = ValidationResult::create();
        $currentLoginRecording = Config::inst()->get('Security', 'login_recording');
        Config::inst()->update('Security', 'login_recording', false); // Disable login_recording for this auth.
        Config::inst()->update('Security', 'login_recording', $currentLoginRecording); // Reset login_recording
        $member = $this->getMember();
        // Continue if we have a valid member
        if ($member && $member instanceof Member) {
            $this->provider->setMember($member);
            // If we know the member, and it's YubiAuth enabled, continue.
            if ($member->MFAEnabled || !empty($token)) {
                return $this->provider->verifyToken($token, $result);
            } elseif (!$member->MFAEnabled) { // We do not have to check the YubiAuth for now.
                $result = $this->provider->verifyNoYubikey($member);
                if ($result->isValid()) {
                    return $member;
                }
            }
            $member->registerFailedLogin();
        }

        $this->updateForm($result);

        return $result;
    }

    /**
     * @return Member
     */
    public function getMember()
    {
        return $this->member;
    }

    /**
     * @param Member $member
     */
    public function setMember($member)
    {
        $this->member = $member;
    }

    /**
     * @param null|ValidationResult $validation
     */
    public function updateForm($validation = null)
    {
        $form = $this->form;
        if ($form) {
            if ($validation === null) {
                // Default validation error.
                $validation = ValidationResult::create(
                    false,
                    _t('YubikeyAuthenticator.ERRORYUBIKEY', 'Yubikey authentication error')
                );
            }
            foreach ($validation->messageList() as $message) {
                $form->sessionMessage($message, 'bad');
            }
        }
    }
}
