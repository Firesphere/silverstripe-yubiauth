<?php
use Firesphere\YubiAuth\QwertyConvertor;

/**
 * Created by PhpStorm.
 * User: simon
 * Date: 13-Nov-16
 * Time: 12:38
 */
class QwertyConvertorTest extends SapphireTest
{

    public function testDvorakConversion()
    {
        $string = QwertyConvertor::convertString('jjjjjjucbuipyhde.cybcpnbiixcjkbbyd.ydenhnjkn');
        $this->assertEquals('ccccccfinfgrtjhdeitnirlnggbicvnnthethdljlcvl', $string);
    }
}