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

namespace Tests\Unit\FreeDSx\Sasl\Mechanism;

use FreeDSx\Sasl\Challenge\ExternalChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\ExternalMechanism;
use FreeDSx\Sasl\Mechanism\MechanismName;
use PHPUnit\Framework\TestCase;

final class ExternalMechanismTest extends TestCase
{
    private ExternalMechanism $mechanism;

    protected function setUp(): void
    {
        $this->mechanism = new ExternalMechanism();
    }

    public function testSecurityStrength(): void
    {
        $strength = $this->mechanism->securityStrength();

        self::assertFalse($strength->supportsPrivacy());
        self::assertFalse($strength->supportsIntegrity());
        self::assertTrue($strength->supportsAuth());
        self::assertFalse($strength->isPlainTextAuth());
        self::assertSame(
            0,
            $strength->maxKeySize(),
        );
    }

    public function testSecurityLayerThrowsAnException(): void
    {
        $this->expectException(SaslException::class);

        $this->mechanism->securityLayer();
    }

    public function testChallengeReturnsTheExternalChallenge(): void
    {
        self::assertInstanceOf(ExternalChallenge::class, $this->mechanism->challenge());
    }

    public function testGetName(): void
    {
        self::assertSame(MechanismName::EXTERNAL, $this->mechanism->getName());
    }
}
