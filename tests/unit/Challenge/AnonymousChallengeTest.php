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

use FreeDSx\Sasl\Challenge\AnonymousChallenge;
use PHPUnit\Framework\TestCase;

final class AnonymousChallengeTest extends TestCase
{
    private AnonymousChallenge $challenge;

    protected function setUp(): void
    {
        $this->challenge = new AnonymousChallenge();
    }

    public function testTheClientChallenge(): void
    {
        $context = $this->challenge->challenge(null, ['username' => 'foo', 'password' => 'bar']);

        self::assertSame('foo', $context->getResponse());
        self::assertTrue($context->isComplete());
        self::assertTrue($context->isAuthenticated());
    }

    public function testTheClientChallengeWithSpecificTrace(): void
    {
        $context = $this->challenge->challenge(null, ['trace' => 'foobar', 'password' => 'bar']);

        self::assertSame('foobar', $context->getResponse());
        self::assertTrue($context->isComplete());
        self::assertTrue($context->isAuthenticated());
    }

    public function testTheServerResponseToTheClientWhenSuccessful(): void
    {
        $challenge = new AnonymousChallenge(true);
        $context = $challenge->challenge('foo');

        self::assertTrue($context->isComplete());
        self::assertTrue($context->isAuthenticated());
        self::assertNull($context->getResponse());
    }
}
