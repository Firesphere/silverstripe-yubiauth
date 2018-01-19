<?php

namespace Firesphere\YubiAuth\Authenticators;

use Exception;
use Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use Firesphere\BootstrapMFA\Handlers\BootstrapMFALoginHandler;
use Firesphere\YubiAuth\Handlers\YubikeyLoginHandler;
use Firesphere\YubiAuth\Helpers\QwertyConvertor;
use Firesphere\YubiAuth\Providers\YubikeyAuthProvider;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\PasswordEncryptor_NotFoundException;
use Yubikey\Response;
use Yubikey\Validate;

/**
 * Class YubikeyAuthenticator
 *
 * Enable Yubikey Authentication for SilverStripe CMS and member-protected pages.
 */
class YubikeyMemberAuthenticator extends BootstrapMFAAuthenticator
{

    /**
     * @var Validate
     */
    protected $yubiService;

    /**
     * @var YubikeyAuthProvider
     */
    protected $provider;

    /**
     * @var string
     */
    private $authenticatorName = 'yubiauth';

    /**
     * Set the provider to a YubikeyAuthProvider instance
     *
     * YubikeyMemberAuthenticator constructor.
     */
    public function __construct()
    {
        if (!$this->provider) {
            $this->provider = Injector::inst()->get(YubikeyAuthProvider::class);
        }
    }

    /**
     * Name of this authenticator
     *
     * @return string
     */
    public static function get_name()
    {
        return _t('YubikeyAuthenticator.TITLE', 'Yubikey 2 factor login');
    }

    /**
     * @return YubikeyAuthProvider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * @param YubikeyAuthProvider $provider
     * @return $this
     */
    public function setProvider($provider)
    {
        $this->provider = $provider;

        return $this;
    }

    public function supportedServices()
    {
        // Bitwise-OR of all the supported services in this Authenticator, to make a bitmask
        return Authenticator::LOGIN | Authenticator::LOGOUT | Authenticator::CHANGE_PASSWORD
            | Authenticator::RESET_PASSWORD | Authenticator::CHECK_PASSWORD;
    }

    /**
     * @inheritdoc
     *
     * @param array $data
     * @param HTTPRequest $request
     * @param ValidationResult $validationResult
     *
     * @return ValidationResult|Member
     * @throws ValidationException
     * @throws PasswordEncryptor_NotFoundException
     */
    public function validateToken($data, $request, &$validationResult = null)
    {
        if (!$validationResult instanceof ValidationResult) {
            $validationResult = ValidationResult::create();
        }

        $memberID = $request->getSession()->get(BootstrapMFALoginHandler::SESSION_KEY . '.MemberID');
        // First, let's see if we know the member
        /** @var Member|null $member */
        $member = Member::get()->filter(['ID' => $memberID])->first();

        // Continue if we have a valid member
        if ($member && $member instanceof Member) {

            // We do not have to check the YubiAuth for now.
            if (!$member->MFAEnabled && empty($data['yubiauth'])) {
                return $this->authenticateNoYubikey($member);
            }

            // If we know the member, and it's YubiAuth enabled, continue.
            return $this->checkYubikey($data, $member);
        }

        $validationResult->addError(_t(__CLASS__ . '.MEMBERNOTFOUND', 'Could not identify member'));
        return $validationResult;
    }

    /**
     * Handle login if the user did not enter a Yubikey string.
     * Will break out and return NULL if the member should use their Yubikey
     *
     * @param  Member $member
     * @return ValidationResult|Member
     * @throws ValidationException
     */
    private function authenticateNoYubikey($member)
    {
        ++$member->NoYubikeyCount;
        $member->write();
        $yubiAuthNoYubi = $this->provider->checkNoYubiAttempts($member);
        if ($yubiAuthNoYubi instanceof ValidationResult) {
            return $yubiAuthNoYubi;
        }

        return $member;
    }

    /**
     * @param $data
     * @param $member
     * @return ValidationResult|Member
     * @throws ValidationException
     * @throws PasswordEncryptor_NotFoundException
     */
    protected function checkYubikey($data, $member)
    {
        /** @var Validate $service */
        $this->yubiService = Injector::inst()->createWithArgs(
            Validate::class,
            [
                Environment::getEnv('YUBIAUTH_APIKEY'),
                Environment::getEnv('YUBIAUTH_CLIENTID'),
            ]
        );

        return $this->authenticateYubikey($data, $member);
    }

    /**
     * Validate a member plus it's yubikey login. It compares the fingerprintt and after that,
     * tries to validate the Yubikey string
     *
     * @param  array $data
     * @param  Member $member
     * @return ValidationResult|Member
     * @throws ValidationException
     * @throws PasswordEncryptor_NotFoundException
     */
    private function authenticateYubikey($data, $member)
    {
        if ($url = Config::inst()->get(self::class, 'AuthURL')) {
            $this->yubiService->setHost($url);
        }
        $yubiCode = QwertyConvertor::convertString($data['yubiauth']);
        $yubiFingerprint = substr($yubiCode, 0, -32);
        $validationResult = ValidationResult::create();

        if ($member->Yubikey) {
            $validationResult = $this->provider->validateToken($member, $yubiFingerprint);
            if (!$validationResult->isValid()) {
                $member->registerFailedLogin();

                return $validationResult;
            }
        }
        try {
            /** @var Response $result */
            $result = $this->yubiService->check($yubiCode);
            $this->updateMember($member, $yubiFingerprint);
        } catch (Exception $e) {
            $validationResult->addError($e->getMessage());

            $member->registerFailedLogin();

            return $validationResult;
        }
        if ($result->success() === true) {
            $this->updateMember($member, $yubiFingerprint);

            return $member;
        }

        $validationResult = ValidationResult::create();
        $validationResult->addError(_t('YubikeyAuthenticator.ERROR', 'Yubikey authentication error'));
        $member->registerFailedLogin();

        return $validationResult;
    }

    /**
     * Update the member to forcefully enable YubiAuth
     * Also, register the Yubikey to the member.
     * Documentation:
     * https://developers.yubico.com/yubikey-val/Getting_Started_Writing_Clients.html
     *
     * @param Member $member
     * @param string $yubiString The Identifier String of the Yubikey
     * @throws ValidationException
     */
    private function updateMember($member, $yubiString)
    {
        $member->registerSuccessfulLogin();
        $member->NoYubikeyCount = 0;

        if (!$member->MFAEnabled) {
            $member->MFAEnabled = true;
        }
        if (!$member->Yubikey) {
            $member->Yubikey = $yubiString;
        }
        $member->write();
    }

    /**
     * @param string $link
     * @return \SilverStripe\Security\MemberAuthenticator\LoginHandler|static
     */
    public function getLoginHandler($link)
    {
        return YubikeyLoginHandler::create($link, $this);
    }
}
