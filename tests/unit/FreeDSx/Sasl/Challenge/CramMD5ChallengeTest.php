<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Challenge\CramMD5Challenge;
use FreeDSx\Sasl\Encoder\CramMD5Encoder;
use PHPUnit\Framework\TestCase;

class CramMD5ChallengeTest extends TestCase
{
    /**
     * @var CramMD5Challenge
     */
    protected $challenge;

    /**
     * @var CramMD5Encoder
     */
    protected $encoder;

    public function setUp(): void
    {
        parent::setUp();
        $this->challenge = new CramMD5Challenge();
        $this->encoder = new CramMD5Encoder();
    }

    public function testChallengeWithFromClientWithServerChallenge()
    {
        $context = $this->challenge->challenge('<foobar>', ['username' => 'foo', 'password' => 'bar']);

        $this->assertEquals('foo e23c893e9de272d4a75e646265768a45', $context->getResponse());
        $this->assertTrue($context->isComplete());
    }

    public function testChallengeWithFromServerWithClientWrongResponse()
    {
        $this->challenge = new CramMD5Challenge(true);
        $validate = function (string $username, string $challenge) {
            return '';
        };
        $this->challenge->challenge();
        $context = $this->challenge->challenge('foo e23c893e9de272d4a75e646265768a45', ['password' => $validate]);

        $this->assertFalse($context->isAuthenticated());
        $this->assertTrue($context->isComplete());
    }

    public function testChallengeWithFromServerWithClientCorrectResponse()
    {
        $this->challenge = new CramMD5Challenge(true);
        $validate = function (string $username, string $challenge) {
            return hash_hmac('md5', $challenge, 'bar');
        };
        // The challenge option is the raw nonce; the encoder wraps it as <foobar>.
        $this->challenge->challenge(null, ['challenge' => 'foobar']);
        $context = $this->challenge->challenge('foo e23c893e9de272d4a75e646265768a45', ['password' => $validate]);

        $this->assertTrue($context->isAuthenticated());
        $this->assertTrue($context->isComplete());
    }

    public function testPasswordCallableReceivesEncodedChallengeMatchingWhatClientUses(): void
    {
        $this->challenge = new CramMD5Challenge(true);

        $challengePassedToCallable = null;
        $validate = function (string $username, string $challenge) use (&$challengePassedToCallable) {
            $challengePassedToCallable = $challenge;

            return hash_hmac(
                'md5',
                $challenge,
                'bar'
            );
        };

        // Server generates challenge with raw nonce 'foobar'; encoder sends '<foobar>' to client.
        $serverContext = $this->challenge->challenge(
            null,
            ['challenge' => 'foobar']
        );
        $encodedChallenge = $serverContext->getResponse();
        $this->assertSame(
            '<foobar>',
            $encodedChallenge
        );

        // Client computes HMAC over the encoded challenge exactly as received.
        $clientChallenge = new CramMD5Challenge(false);
        $clientContext = $clientChallenge->challenge(
            $encodedChallenge,
            ['username' => 'foo', 'password' => 'bar']
        );

        // Server validates the client response.
        $this->challenge->challenge(
            $clientContext->getResponse(),
            ['password' => $validate]
        );

        // The callable must receive the encoded form so it can compute the same digest as the client.
        $this->assertSame(
            '<foobar>',
            $challengePassedToCallable
        );
        $this->assertTrue($this->challenge->challenge()->isAuthenticated());
    }

    public function testChallengeWithFromServerWithInitialChallenge()
    {
        $this->challenge = new CramMD5Challenge(true);
        $context = $this->challenge->challenge();

        $this->assertNotNull($context->getResponse());
        $this->assertFalse($context->isComplete());
    }
}
