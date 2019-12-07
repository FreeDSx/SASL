<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl\Mechanism;

use FreeDSx\Sasl\Challenge\AnonymousChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\AnonymousMechanism;
use PHPUnit\Framework\TestCase;

class AnonymousMechanismTest extends TestCase
{
    /**
     * @var AnonymousMechanism
     */
    protected $mechanism;

    public function setUp()
    {
        parent::setUp();
        $this->mechanism = new AnonymousMechanism();
    }

    public function testSupportsIntegrityReturnsFalse()
    {
        $this->assertFalse($this->mechanism->supportsIntegrity());
    }

    public function testSupportsPrivacyReturnsFalse()
    {
        $this->assertFalse($this->mechanism->supportsPrivacy());
    }

    public function testSecurityThrowsAnException()
    {
        $this->expectException(SaslException::class);

        $this->mechanism->securityLayer();
    }

    public function testChallengeReturnsThePlainChallenge()
    {
        $this->assertInstanceOf(AnonymousChallenge::class, $this->mechanism->challenge());
    }

    public function testGetName()
    {
        $this->assertEquals('ANONYMOUS', $this->mechanism->getName());
    }
}