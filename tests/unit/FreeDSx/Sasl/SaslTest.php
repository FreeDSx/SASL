<?php
/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl;

use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\MechanismInterface;
use FreeDSx\Sasl\Sasl;
use PHPUnit\Framework\TestCase;

class SaslTest extends TestCase
{
    /**
     * @var Sasl
     */
    protected $sasl;

    public function setUp()
    {
        $this->sasl = new Sasl();
    }

    public function testAdd()
    {
        $mechMock = $this->createMock(MechanismInterface::class);
        $mechMock->method('getName')->willReturn('FOO');

        $this->sasl->add($mechMock);
        $this->assertEquals($mechMock, $this->sasl->get('FOO'));
    }

    public function testMechanisms()
    {
        $mechs = $this->sasl->mechanisms();

        $this->assertArrayHasKey('DIGEST-MD5', $mechs);
        $this->assertCount(1, $mechs);
    }

    public function testRemove()
    {
        $this->sasl->remove('DIGEST-MD5');

        $this->assertFalse($this->sasl->supports('DIGEST-MD5'));
    }

    public function testGet()
    {
        $this->assertInstanceOf(DigestMD5Mechanism::class, $this->sasl->get('DIGEST-MD5'));
    }

    public function testSupportedOption()
    {
        $sasl = new Sasl(['supported' => ['foo']]);
        $this->assertEmpty($sasl->mechanisms());

        $sasl = new Sasl(['supported' => 'DIGEST-MD5']);
        $this->assertCount(1, $sasl->mechanisms());
    }
}