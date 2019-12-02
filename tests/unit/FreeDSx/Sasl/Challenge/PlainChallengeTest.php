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

use FreeDSx\Sasl\Challenge\PlainChallenge;
use PHPUnit\Framework\TestCase;

class PlainChallengeTest extends TestCase
{
    /**
     * @var PlainChallenge
     */
    protected $challenge;

    public function setUp()
    {
        parent::setUp();
        $this->challenge = new PlainChallenge();
    }

    public function testTheClientChallenge()
    {
        $context = $this->challenge->challenge(null, ['username' => 'foo', 'password' => 'bar']);


        $this->assertEquals("foo\x00foo\x00bar", $context->getResponse());
        $this->assertTrue($context->isComplete());
    }

    public function testTheServerResponseToTheClientWhenSuccessful()
    {
        $this->challenge = new PlainChallenge(true);
        $validate = function (string $authzid, string $authcid, string $password) {
            return true;
        };

        $context = $this->challenge->challenge("foo\x00foo\x00bar", ['validate' => $validate]);
        $this->assertTrue($context->isComplete());
        $this->assertTrue($context->isAuthenticated());
        $this->assertNull($context->getResponse());
    }

    public function testTheServerResponseToTheClientWhenNotSuccessful()
    {
        $this->challenge = new PlainChallenge(true);
        $validate = function (string $authzid, string $authcid, string $password) {
            return false;
        };

        $context = $this->challenge->challenge("foo\x00foo\x00bar", ['validate' => $validate]);
        $this->assertTrue($context->isComplete());
        $this->assertFalse($context->isAuthenticated());
        $this->assertNull($context->getResponse());
    }
}
