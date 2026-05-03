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

namespace Tests\Unit\FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Challenge\PlainChallenge;
use PHPUnit\Framework\TestCase;

final class PlainChallengeTest extends TestCase
{
    private PlainChallenge $challenge;

    protected function setUp(): void
    {
        $this->challenge = new PlainChallenge();
    }

    public function testTheClientChallenge(): void
    {
        $context = $this->challenge->challenge(null, ['username' => 'foo', 'password' => 'bar']);

        self::assertSame("foo\x00foo\x00bar", $context->getResponse());
        self::assertTrue($context->isComplete());
    }

    public function testTheServerResponseToTheClientWhenSuccessful(): void
    {
        $serverChallenge = new PlainChallenge(true);
        $validate = static fn (string $authzid, string $authcid, string $password): bool => true;

        $context = $serverChallenge->challenge("foo\x00foo\x00bar", ['validate' => $validate]);

        self::assertTrue($context->isComplete());
        self::assertTrue($context->isAuthenticated());
        self::assertNull($context->getResponse());
    }

    public function testTheServerResponseToTheClientWhenNotSuccessful(): void
    {
        $serverChallenge = new PlainChallenge(true);
        $validate = static fn (string $authzid, string $authcid, string $password): bool => false;

        $context = $serverChallenge->challenge("foo\x00foo\x00bar", ['validate' => $validate]);

        self::assertTrue($context->isComplete());
        self::assertFalse($context->isAuthenticated());
        self::assertNull($context->getResponse());
    }
}
