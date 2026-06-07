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

use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\MechanismInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\SaslOptions;
use FreeDSx\Sasl\Sasl;
use PHPUnit\Framework\TestCase;

final class SaslTest extends TestCase
{
    private Sasl $sasl;

    protected function setUp(): void
    {
        $this->sasl = new Sasl();
    }

    public function testAdd(): void
    {
        $mechMock = $this->createMock(MechanismInterface::class);
        $mechMock->method('getName')->willReturn(MechanismName::ANONYMOUS);

        $this->sasl->add($mechMock);
        self::assertSame($mechMock, $this->sasl->get(MechanismName::ANONYMOUS));
    }

    public function testMechanisms(): void
    {
        $mechs = $this->sasl->mechanisms();

        self::assertArrayHasKey('DIGEST-MD5', $mechs);
        self::assertArrayHasKey('CRAM-MD5', $mechs);
        self::assertArrayHasKey('PLAIN', $mechs);
        self::assertArrayHasKey('ANONYMOUS', $mechs);
        self::assertArrayHasKey('EXTERNAL', $mechs);
        self::assertCount(
            17,
            $mechs,
        );
    }

    public function testRemove(): void
    {
        $this->sasl->remove(MechanismName::DIGEST_MD5);

        self::assertFalse($this->sasl->supports(MechanismName::DIGEST_MD5));
    }

    public function testGetDigestMD5(): void
    {
        self::assertInstanceOf(DigestMD5Mechanism::class, $this->sasl->get(MechanismName::DIGEST_MD5));
    }

    public function testGetCramMD5(): void
    {
        self::assertInstanceOf(CramMD5Mechanism::class, $this->sasl->get(MechanismName::CRAM_MD5));
    }

    public function testSupportedOption(): void
    {
        $sasl = new Sasl(new SaslOptions(supported: [MechanismName::DIGEST_MD5]));
        self::assertCount(1, $sasl->mechanisms());
    }

    public function testSelect(): void
    {
        self::assertInstanceOf(DigestMD5Mechanism::class, $this->sasl->select());
        self::assertInstanceOf(CramMD5Mechanism::class, $this->sasl->select([MechanismName::CRAM_MD5]));
    }
}
