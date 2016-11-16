<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\QwertyConvertor;
use PHPUnit_Framework_TestCase;
use SapphireTest;

/**
 * Class QwertyConvertorTest
 *
 * @mixin PHPUnit_Framework_TestCase
 */
class QwertyConvertorTest extends SapphireTest
{

    public function testCapitalisationConversion()
    {
        $string = QwertyConvertor::convertString('CCCCCCFINFGRTJHDEITNIRLNGGBICVNNTHETHDLJLCVL');
        $this->assertEquals('ccccccfinfgrtjhdeitnirlnggbicvnnthethdljlcvl', $string);
    }

    public function testDvorakConversion()
    {
        $string = QwertyConvertor::convertString('jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn');
        $this->assertEquals('ccccccfinfgrtjhdeitnirlnggbicvnnthethdljlcvl', $string);
    }
}