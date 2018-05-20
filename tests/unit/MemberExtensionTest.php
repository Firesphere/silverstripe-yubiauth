<?php
/**
 * Created by PhpStorm.
 * User: simon
 * Date: 15-May-18
 * Time: 20:49
 */

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\Extensions\MemberExtension;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\NumericField;
use SilverStripe\Security\Member;

class MemberExtensionTest extends SapphireTest
{
    public function testLabels()
    {
        $labels = [];

        /** @var MemberExtension $extension */
        $extension = Injector::inst()->get(MemberExtension::class);
        $extension->updateFieldLabels($labels);

        $expected = [
            'Yubikey'        => 'Yubikey code',
            'NoYubikeyCount' => 'Login count without yubikey',
        ];

        $this->assertEquals($expected, $labels);
    }

    public function testUpdateCMSFields()
    {
        $member = Member::create();

        $fields = $member->getCMSFields();

        $this->assertInstanceOf(NumericField::class, $fields->dataFieldByName('NoYubikeyCount'));
        $this->assertNull($fields->dataFieldByName('Yubikey'));
    }
}
