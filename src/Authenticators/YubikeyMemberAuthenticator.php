<?php

namespace Firesphere\YubiAuth\Authenticators;

use Firesphere\BootstrapMFA\Authenticators\BootstrapMFAAuthenticator;
use Firesphere\BootstrapMFA\Handlers\BootstrapMFALoginHandler;
use Firesphere\YubiAuth\Handlers\YubikeyLoginHandler;
use Firesphere\YubiAuth\Providers\YubikeyAuthProvider;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\LoginHandler;
use Yubikey\Validate;

/**
 * Class YubikeyAuthenticator
 *
 * Enable Yubikey Authentication for SilverStripe CMS and member-protected pages.
 */
class YubikeyMemberAuthenticator extends BootstrapMFAAuthenticator
{

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
        return _t(self::class . '.TITLE', 'Yubikey 2 factor login');
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

    /**
     * @return int
     */
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
        if ($member instanceof Member) {

            // We do not have to check the YubiAuth for this situation.
            if (!$member->MFAEnabled && empty($data['yubiauth'])) {
                return $this->authenticateNoYubikey($member);
            }

            // If we know the member, and it's YubiAuth enabled, continue.
            $member = $this->provider->checkYubikey($data, $member, $validationResult);
        }

        $validationResult->addError(_t(self::class . '.MEMBERNOTFOUND', 'Could not identify member'));

        return $member;
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
     * @param string $link
     * @return LoginHandler|static
     */
    public function getLoginHandler($link)
    {
        return YubikeyLoginHandler::create($link, $this);
    }
}
