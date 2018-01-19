<?php

namespace Firesphere\YubiAuth\Tests;

use Firesphere\YubiAuth\Helpers\QwertyConvertor;
use PHPUnit_Framework_TestCase;
use SilverStripe\Dev\SapphireTest;

/**
 * Class QwertyConvertorTest
 *
 * Uses _INVALID_ Yubikey Authentication strings
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

    public function testAzertyConversion()
    {
        $string = QwertyConvertor::convertString('ccccccfinfgrtjhdeitnirl°ggbicvnnthethdljlcvl');
        $this->assertEquals('vvvvvvfimfgrtjhdeitmirl+Qggnivbmmthethdljlvbl', $string);
        $string = QwertyConvertor::convertString('ccccccfinfgrtjhdeitnirl¨ggbicvnnthethdljlcvl');
        $this->assertEquals('vvvvvvfimfgrtjhdeitmirl+Sggnivbmmthethdljlvbl', $string);
        $string = QwertyConvertor::convertString('ccccccfinfgrtjhdeitnirl$ggbicvnnthethdljlcvl');
        $this->assertEquals('vvvvvvfimfgrtjhdeitmirl]ggnivbmmthethdljlvbl', $string);
        $string = QwertyConvertor::convertString('ccccccfinfgrtjhdeitnirl$°gb¨cvnnthethdljlcvl');
        $this->assertEquals('vvvvvvfimfgrtjhdeitmirl]+Qgn+Svbmmthethdljlvbl', $string);
    }
}
