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

use Closure;
use FreeDSx\Sasl\Challenge\CramMD5Challenge;
use FreeDSx\Sasl\Options\CramMD5Options;
use PHPUnit\Framework\TestCase;

final class CramMD5ChallengeTest extends TestCase
{
    private CramMD5Challenge $challenge;

    protected function setUp(): void
    {
        $this->challenge = new CramMD5Challenge();
    }

    public function testChallengeWithFromClientWithServerChallenge(): void
    {
        $context = $this->challenge->challenge(
            '<foobar>',
            (new CramMD5Options())->setUsername('foo')->setPassword('bar'),
        );

        self::assertSame('foo e23c893e9de272d4a75e646265768a45', $context->getResponse());
        self::assertTrue($context->isComplete());
    }

    public function testChallengeWithFromServerWithClientWrongResponse(): void
    {
        $serverChallenge = new CramMD5Challenge(true);
        $validate = static fn (string $username, string $challenge): string => '';
        $serverChallenge->challenge();
        $context = $serverChallenge->challenge(
            'foo e23c893e9de272d4a75e646265768a45',
            (new CramMD5Options())->setPasswordCallback(Closure::fromCallable($validate)),
        );

        self::assertFalse($context->isAuthenticated());
        self::assertTrue($context->isComplete());
    }

    public function testChallengeWithFromServerWithClientCorrectResponse(): void
    {
        $serverChallenge = new CramMD5Challenge(true);
        $validate = static fn (string $username, string $challenge): string => hash_hmac('md5', $challenge, 'bar');
        // The challenge option is the raw nonce; the encoder wraps it as <foobar>.
        $serverChallenge->challenge(null, (new CramMD5Options())->setChallenge('foobar'));
        $context = $serverChallenge->challenge(
            'foo e23c893e9de272d4a75e646265768a45',
            (new CramMD5Options())->setPasswordCallback(Closure::fromCallable($validate)),
        );

        self::assertTrue($context->isAuthenticated());
        self::assertTrue($context->isComplete());
    }

    public function testPasswordCallableReceivesEncodedChallengeMatchingWhatClientUses(): void
    {
        $serverChallenge = new CramMD5Challenge(true);

        $challengePassedToCallable = null;
        $validate = static function (string $username, string $challenge) use (&$challengePassedToCallable): string {
            $challengePassedToCallable = $challenge;

            return hash_hmac('md5', $challenge, 'bar');
        };

        // Server generates challenge with raw nonce 'foobar'; encoder sends '<foobar>' to client.
        $serverContext = $serverChallenge->challenge(null, (new CramMD5Options())->setChallenge('foobar'));
        $encodedChallenge = $serverContext->getResponse();
        self::assertSame('<foobar>', $encodedChallenge);

        // Client computes HMAC over the encoded challenge exactly as received.
        $clientChallenge = new CramMD5Challenge(false);
        $clientContext = $clientChallenge->challenge(
            $encodedChallenge,
            (new CramMD5Options())->setUsername('foo')->setPassword('bar'),
        );

        // Server validates the client response.
        $serverChallenge->challenge(
            $clientContext->getResponse(),
            (new CramMD5Options())->setPasswordCallback(Closure::fromCallable($validate)),
        );

        // The callable must receive the encoded form so it can compute the same digest as the client.
        self::assertSame('<foobar>', $challengePassedToCallable);
        self::assertTrue($serverChallenge->challenge()->isAuthenticated());
    }

    public function testChallengeWithFromServerWithInitialChallenge(): void
    {
        $serverChallenge = new CramMD5Challenge(true);
        $context = $serverChallenge->challenge();

        self::assertNotNull($context->getResponse());
        self::assertFalse($context->isComplete());
    }
}
