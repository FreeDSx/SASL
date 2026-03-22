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

use FreeDSx\Sasl\Challenge\ScramChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\ScramMechanism;
use PHPUnit\Framework\TestCase;

class ScramMechanismTest extends TestCase
{
    /**
     * @var ScramMechanism
     */
    private $mechanism;

    public function setUp(): void
    {
        parent::setUp();

        $this->mechanism = new ScramMechanism(ScramMechanism::SHA256);
    }

    public function testGetName(): void
    {
        $this->assertSame(
            'SCRAM-SHA-256',
            $this->mechanism->getName()
        );
    }

    /**
     * @dataProvider variantNameProvider
     */
    public function testGetNameForAllVariants(string $name): void
    {
        $mechanism = new ScramMechanism($name);

        $this->assertSame(
            $name,
            $mechanism->getName()
        );
    }

    public function variantNameProvider(): array
    {
        return [
            [ScramMechanism::SHA1],
            [ScramMechanism::SHA1_PLUS],
            [ScramMechanism::SHA224],
            [ScramMechanism::SHA224_PLUS],
            [ScramMechanism::SHA256],
            [ScramMechanism::SHA256_PLUS],
            [ScramMechanism::SHA384],
            [ScramMechanism::SHA384_PLUS],
            [ScramMechanism::SHA512],
            [ScramMechanism::SHA512_PLUS],
            [ScramMechanism::SHA3_512],
            [ScramMechanism::SHA3_512_PLUS],
        ];
    }

    public function testSecurityStrength(): void
    {
        $strength = $this->mechanism->securityStrength();

        $this->assertFalse($strength->supportsPrivacy());
        $this->assertFalse($strength->supportsIntegrity());
        $this->assertTrue($strength->supportsAuth());
        $this->assertFalse($strength->isPlainTextAuth());
        $this->assertSame(0, $strength->maxKeySize());
    }

    public function testSecurityLayerThrowsAnException(): void
    {
        $this->expectException(SaslException::class);

        $this->mechanism->securityLayer();
    }

    public function testChallengeReturnsScramChallenge(): void
    {
        $this->assertInstanceOf(ScramChallenge::class, $this->mechanism->challenge());
    }

    public function testInvalidVariantThrowsAnException(): void
    {
        $this->expectException(SaslException::class);

        new ScramMechanism('SCRAM-MD5');
    }

    public function testToString(): void
    {
        $this->assertSame(
            'SCRAM-SHA-256',
            (string) $this->mechanism
        );
    }
}
