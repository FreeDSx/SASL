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

    public function setUp()
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
        $this->challenge->challenge(null, ['challenge' => '<foobar>']);
        $context = $this->challenge->challenge('foo e23c893e9de272d4a75e646265768a45', ['password' => $validate]);

        $this->assertTrue($context->isAuthenticated());
        $this->assertTrue($context->isComplete());
    }

    public function testChallengeWithFromServerWithInitialChallenge()
    {
        $this->challenge = new CramMD5Challenge(true);
        $context = $this->challenge->challenge();

        $this->assertNotNull($context->getResponse());
        $this->assertFalse($context->isComplete());
    }
}
