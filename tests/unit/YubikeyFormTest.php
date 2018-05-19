<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\Forms\YubikeyForm;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Dev\SapphireTest;

class YubikeyFormTest extends SapphireTest
{
    /**
     * @var YubikeyForm;
     */
    protected $form;

    public function testBackURL()
    {
        $fields = $this->form->getFormFields();

        $this->assertNotNull($fields->dataFieldByName('BackURL'));
    }

    public function testAuthenticatorName()
    {
        $this->assertEquals('Yubikey authentication', $this->form->getAuthenticatorName());
    }

    protected function setUp()
    {
        parent::setUp();
        $backURL = '/test/url';
        $request = new HTTPRequest('GET', '/', ['BackURL' => $backURL]);
        $request->setSession(new Session(['hi' => 'bye']));
        $controller = new Controller();
        $controller->setRequest($request);
        $this->form = YubikeyForm::create($controller);
    }
}
