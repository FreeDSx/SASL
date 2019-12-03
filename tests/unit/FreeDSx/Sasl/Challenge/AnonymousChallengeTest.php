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

use FreeDSx\Sasl\Challenge\AnonymousChallenge;
use PHPUnit\Framework\TestCase;

class AnonymousChallengeTest extends TestCase
{
    /**
     * @var AnonymousChallenge
     */
    protected $challenge;

    public function setUp()
    {
        parent::setUp();
        $this->challenge = new AnonymousChallenge();
    }

    public function testTheClientChallenge()
    {
        $context = $this->challenge->challenge(null, ['username' => 'foo', 'password' => 'bar']);


        $this->assertEquals("foo", $context->getResponse());
        $this->assertTrue($context->isComplete());
        $this->assertTrue($context->isAuthenticated());
    }

    public function testTheClientChallengeWithSpecificTrace()
    {
        $context = $this->challenge->challenge(null, ['trace' => 'foobar', 'password' => 'bar']);

        $this->assertEquals("foobar", $context->getResponse());
        $this->assertTrue($context->isComplete());
        $this->assertTrue($context->isAuthenticated());
    }

    public function testTheServerResponseToTheClientWhenSuccessful()
    {
        $this->challenge = new AnonymousChallenge(true);
        $context = $this->challenge->challenge("foo");
        $this->assertTrue($context->isComplete());
        $this->assertTrue($context->isAuthenticated());
        $this->assertNull($context->getResponse());
    }
}
