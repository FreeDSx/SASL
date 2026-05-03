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

namespace Tests\Unit\FreeDSx\Sasl\Mechanism;

use FreeDSx\Sasl\Challenge\DigestMD5Challenge;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\Security\DigestMD5SecurityLayer;
use PHPUnit\Framework\TestCase;

final class DigestMD5MechanismTest extends TestCase
{
    private DigestMD5Mechanism $mech;

    protected function setUp(): void
    {
        $this->mech = new DigestMD5Mechanism();
    }

    public function testToString(): void
    {
        self::assertSame('DIGEST-MD5', (string) $this->mech);
    }

    public function testSecurityStrength(): void
    {
        $strength = $this->mech->securityStrength();

        self::assertTrue($strength->supportsPrivacy());
        self::assertTrue($strength->supportsIntegrity());
        self::assertTrue($strength->supportsAuth());
        self::assertFalse($strength->isPlainTextAuth());
        self::assertSame(128, $strength->maxKeySize());
    }

    public function testSecurity(): void
    {
        self::assertInstanceOf(DigestMD5SecurityLayer::class, $this->mech->securityLayer());
    }

    public function testChallenge(): void
    {
        self::assertInstanceOf(DigestMD5Challenge::class, $this->mech->challenge());
    }

    public function testGetName(): void
    {
        self::assertSame(MechanismName::DIGEST_MD5, $this->mech->getName());
    }

    public function testComputeResponse(): void
    {
        $challenge = new Message([
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'realm' => 'huh-sys',
            'qop' => ['auth', 'auth-int', 'auth-conf'],
            'cipher' => ['rc4-40', 'rc4-56', 'rc4', 'des', '3des'],
            'maxbuf' => '65536',
            'charset' => 'utf-8',
            'algorithm' => 'md5-sess',
        ]);
        $response = new Message([
            'username' => 'WillifoA',
            'realm' => 'huh-sys',
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'cnonce' => 'jSo4loL8WWrHo50BImsqjSRBKMAoXDDXrjNGCfY2v+Q=',
            'nc' => 1,
            'qop' => 'auth-conf',
            'cipher' => 'rc4',
            'maxbuf' => '16777215',
            'digest-uri' => 'ldap/huh-sys',
        ]);

        self::assertSame(
            '16c0ee7bfa5fcc3b2d19b50f17ebb8f2',
            DigestMD5Mechanism::computeResponse('Password1', $challenge, $response, false),
        );
    }

    public function testComputeA1(): void
    {
        $challenge = new Message([
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'realm' => 'huh-sys',
            'qop' => ['auth', 'auth-int', 'auth-conf'],
            'cipher' => ['rc4-40', 'rc4-56', 'rc4', 'des', '3des'],
            'maxbuf' => '65536',
            'charset' => 'utf-8',
            'algorithm' => 'md5-sess',
        ]);
        $response = new Message([
            'username' => 'WillifoA',
            'realm' => 'huh-sys',
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'cnonce' => 'jSo4loL8WWrHo50BImsqjSRBKMAoXDDXrjNGCfY2v+Q=',
            'nc' => 1,
            'qop' => 'auth-conf',
            'cipher' => 'rc4',
            'maxbuf' => '16777215',
            'digest-uri' => 'ldap/huh-sys',
        ]);

        self::assertSame(
            'c951ca891eaedcf85e8c6c9d8763406d',
            DigestMD5Mechanism::computeA1('Password1', $challenge, $response),
        );
    }
}
