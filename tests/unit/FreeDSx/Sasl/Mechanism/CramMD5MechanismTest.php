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

use FreeDSx\Sasl\Challenge\CramMD5Challenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use PHPUnit\Framework\TestCase;

class CramMD5MechanismTest extends TestCase
{
    protected $mechanism;

    public function setUp()
    {
        parent::setUp();
        $this->mechanism = new CramMD5Mechanism();
    }

    public function testSecurityStrength()
    {
        $strength = $this->mechanism->securityStrength();

        $this->assertFalse($strength->supportsPrivacy());
        $this->assertFalse($strength->supportsIntegrity());
        $this->assertTrue($strength->supportsAuth());
        $this->assertFalse($strength->isPlainTextAuth());
        $this->assertEquals(0, $strength->maxKeySize());
    }

    public function testSecurityThrowsAnException()
    {
        $this->expectException(SaslException::class);

        $this->mechanism->securityLayer();
    }

    public function testChallenge()
    {
        $challenge = $this->mechanism->challenge();

        $this->assertInstanceOf(CramMD5Challenge::class, $challenge);
    }

    public function testGetName()
    {
        $this->assertEquals('CRAM-MD5', $this->mechanism->getName());
    }
}
