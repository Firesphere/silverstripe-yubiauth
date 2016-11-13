<?php
use Firesphere\YubiAuth\QwertyConvertor;

/**
 * Class QwertyConvertorTest
 *
 * @mixin PHPUnit_Framework_TestCase
 */
class QwertyConvertorTest extends SapphireTest
{

    public function testDvorakConversion()
    {
        $string = QwertyConvertor::convertString('jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn');
        $this->assertEquals('ccccccfinfgrtjhdeitnirlnggbicvnnthethdljlcvl', $string);
    }
}