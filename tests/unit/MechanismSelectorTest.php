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

use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\AnonymousMechanism;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use FreeDSx\Sasl\MechanismSelector;
use PHPUnit\Framework\TestCase;

final class MechanismSelectorTest extends TestCase
{
    private MechanismSelector $selector;

    protected function setUp(): void
    {
        $this->selector = new MechanismSelector([
            new PlainMechanism(),
            new CramMD5Mechanism(),
            new AnonymousMechanism(),
            new DigestMD5Mechanism(),
        ]);
    }

    public function testSelectWithNoChoicesSpecified(): void
    {
        $choice = $this->selector->select();

        self::assertSame(MechanismName::DIGEST_MD5, $choice->getName());
    }

    public function testSelectWithAnonymousOrAuthOnly(): void
    {
        $choice = $this->selector->select([MechanismName::CRAM_MD5, MechanismName::ANONYMOUS]);

        self::assertSame(MechanismName::CRAM_MD5, $choice->getName());
    }

    public function testSelectWithUseIntegrity(): void
    {
        $choice = $this->selector->select([], ['use_integrity' => true]);

        self::assertSame(MechanismName::DIGEST_MD5, $choice->getName());
    }

    public function testSelectWithUsePrivacy(): void
    {
        $choice = $this->selector->select([], ['use_privacy' => true]);

        self::assertSame(MechanismName::DIGEST_MD5, $choice->getName());
    }

    public function testSelectWithoutPrivacyOrIntegrityStillSelectsTheBetterChoiceForAuth(): void
    {
        $choice = $this->selector->select([], ['use_integrity' => false, 'use_privacy' => false]);

        self::assertSame(MechanismName::DIGEST_MD5, $choice->getName());
    }

    public function testSelectChoosesAuthChoicesCorrectly(): void
    {
        $choice = $this->selector->select([MechanismName::ANONYMOUS, MechanismName::PLAIN, MechanismName::CRAM_MD5]);

        self::assertSame(MechanismName::CRAM_MD5, $choice->getName());
    }

    public function testSelectChoosesAuthOverAnon(): void
    {
        $choice = $this->selector->select([MechanismName::ANONYMOUS, MechanismName::PLAIN]);

        self::assertSame(MechanismName::PLAIN, $choice->getName());
    }

    public function testSelectThrowsAnExceptionIfNoMechsMeetsIntegrityRequirements(): void
    {
        $this->expectException(SaslException::class);

        $this->selector->select(
            [MechanismName::ANONYMOUS, MechanismName::PLAIN, MechanismName::CRAM_MD5],
            ['use_integrity' => true],
        );
    }

    public function testSelectThrowsAnExceptionIfNoMechsMeetsPrivacyRequirements(): void
    {
        $this->expectException(SaslException::class);

        $this->selector->select(
            [MechanismName::ANONYMOUS, MechanismName::PLAIN, MechanismName::CRAM_MD5],
            ['use_privacy' => true],
        );
    }

    public function testSelectThrowsAnExceptionIfNoSupportedMechsAreFound(): void
    {
        $this->expectException(SaslException::class);

        $this->selector->select([MechanismName::SCRAM_SHA1]);
    }
}
