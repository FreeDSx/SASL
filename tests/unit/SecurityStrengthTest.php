<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Unit\FreeDSx\Sasl;

use FreeDSx\Sasl\SecurityStrength;
use PHPUnit\Framework\TestCase;

final class SecurityStrengthTest extends TestCase
{
    private SecurityStrength $strength;

    protected function setUp(): void
    {
        $this->strength = new SecurityStrength(
            supportsIntegrity: true,
            supportsPrivacy: true,
            supportsAuth: true,
            isPlainTextAuth: false,
            maxKeySize: 512,
        );
    }

    public function testSupportsIntegrity(): void
    {
        self::assertTrue($this->strength->supportsIntegrity());
    }

    public function testSupportsPrivacy(): void
    {
        self::assertTrue($this->strength->supportsPrivacy());
    }

    public function testSupportsAuth(): void
    {
        self::assertTrue($this->strength->supportsAuth());
    }

    public function testIsPlainTextAuth(): void
    {
        self::assertFalse($this->strength->isPlainTextAuth());
    }

    public function testMaxKeySize(): void
    {
        self::assertSame(512, $this->strength->maxKeySize());
    }
}
