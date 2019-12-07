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

use FreeDSx\Sasl\SecurityStrength;
use PHPUnit\Framework\TestCase;

class SecurityStrengthTest extends TestCase
{
    protected $strength;

    public function setUp()
    {
        parent::setUp();
        $this->strength = new SecurityStrength(
            true,
            true,
            true,
            false,
            512
        );
    }

    public function testSupportsIntegrity()
    {
        $this->assertTrue($this->strength->supportsIntegrity());
    }

    public function testSupportsPrivacy()
    {
        $this->assertTrue($this->strength->supportsPrivacy());
    }

    public function testSupportsAuth()
    {
        $this->assertTrue($this->strength->supportsAuth());
    }

    public function testIsPlainTextAuth()
    {
        $this->assertFalse($this->strength->isPlainTextAuth());
    }

    public function testMaxKeySize()
    {
        $this->assertEquals(512, $this->strength->maxKeySize());
    }
}
