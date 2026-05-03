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

use FreeDSx\Sasl\Challenge\AnonymousChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\AnonymousMechanism;
use FreeDSx\Sasl\Mechanism\MechanismName;
use PHPUnit\Framework\TestCase;

final class AnonymousMechanismTest extends TestCase
{
    private AnonymousMechanism $mechanism;

    protected function setUp(): void
    {
        $this->mechanism = new AnonymousMechanism();
    }

    public function testSecurityStrength(): void
    {
        $strength = $this->mechanism->securityStrength();

        self::assertFalse($strength->supportsPrivacy());
        self::assertFalse($strength->supportsIntegrity());
        self::assertFalse($strength->supportsAuth());
        self::assertFalse($strength->isPlainTextAuth());
        self::assertSame(0, $strength->maxKeySize());
    }

    public function testSecurityThrowsAnException(): void
    {
        $this->expectException(SaslException::class);

        $this->mechanism->securityLayer();
    }

    public function testChallengeReturnsTheAnonymousChallenge(): void
    {
        self::assertInstanceOf(AnonymousChallenge::class, $this->mechanism->challenge());
    }

    public function testGetName(): void
    {
        self::assertSame(MechanismName::ANONYMOUS, $this->mechanism->getName());
    }
}
