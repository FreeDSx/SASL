<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl\Mechanism;

use FreeDSx\Sasl\Challenge\PlainChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use PHPUnit\Framework\TestCase;

class PlainMechanismTest extends TestCase
{
    protected $mechanism;

    public function setUp()
    {
        parent::setUp();
        $this->mechanism = new PlainMechanism();
    }

    public function testSecurityStrength()
    {
        $strength = $this->mechanism->securityStrength();

        $this->assertFalse($strength->supportsPrivacy());
        $this->assertFalse($strength->supportsIntegrity());
        $this->assertTrue($strength->supportsAuth());
        $this->assertTrue($strength->isPlainTextAuth());
        $this->assertEquals(0, $strength->maxKeySize());
    }

    public function testSecurityThrowsAnException()
    {
        $this->expectException(SaslException::class);

        $this->mechanism->securityLayer();
    }

    public function testChallengeReturnsThePlainChallenge()
    {
        $this->assertInstanceOf(PlainChallenge::class, $this->mechanism->challenge());
    }

    public function testGetName()
    {
        $this->assertEquals('PLAIN', $this->mechanism->getName());
    }
}
