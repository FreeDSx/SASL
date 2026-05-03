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

use FreeDSx\Sasl\Challenge\ScramChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Mechanism\ScramMechanism;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ScramMechanismTest extends TestCase
{
    private ScramMechanism $mechanism;

    protected function setUp(): void
    {
        $this->mechanism = new ScramMechanism(MechanismName::SCRAM_SHA256);
    }

    public function testGetName(): void
    {
        self::assertSame(MechanismName::SCRAM_SHA256, $this->mechanism->getName());
    }

    #[DataProvider('variantNameProvider')]
    public function testGetNameForAllVariants(MechanismName $variant): void
    {
        $mechanism = new ScramMechanism($variant);

        self::assertSame($variant, $mechanism->getName());
    }

    /**
     * @return array<int, array{MechanismName}>
     */
    public static function variantNameProvider(): array
    {
        return [
            [MechanismName::SCRAM_SHA1],
            [MechanismName::SCRAM_SHA1_PLUS],
            [MechanismName::SCRAM_SHA224],
            [MechanismName::SCRAM_SHA224_PLUS],
            [MechanismName::SCRAM_SHA256],
            [MechanismName::SCRAM_SHA256_PLUS],
            [MechanismName::SCRAM_SHA384],
            [MechanismName::SCRAM_SHA384_PLUS],
            [MechanismName::SCRAM_SHA512],
            [MechanismName::SCRAM_SHA512_PLUS],
            [MechanismName::SCRAM_SHA3_512],
            [MechanismName::SCRAM_SHA3_512_PLUS],
        ];
    }

    public function testSecurityStrength(): void
    {
        $strength = $this->mechanism->securityStrength();

        self::assertFalse($strength->supportsPrivacy());
        self::assertFalse($strength->supportsIntegrity());
        self::assertTrue($strength->supportsAuth());
        self::assertFalse($strength->isPlainTextAuth());
        self::assertSame(0, $strength->maxKeySize());
    }

    public function testSecurityLayerThrowsAnException(): void
    {
        $this->expectException(SaslException::class);

        $this->mechanism->securityLayer();
    }

    public function testChallengeReturnsScramChallenge(): void
    {
        self::assertInstanceOf(ScramChallenge::class, $this->mechanism->challenge());
    }

    public function testNonScramMechanismThrowsAnException(): void
    {
        $this->expectException(SaslException::class);

        new ScramMechanism(MechanismName::PLAIN);
    }

    public function testToString(): void
    {
        self::assertSame('SCRAM-SHA-256', (string) $this->mechanism);
    }
}
