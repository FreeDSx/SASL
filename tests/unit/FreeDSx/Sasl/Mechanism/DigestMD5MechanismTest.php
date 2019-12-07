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

use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use PHPUnit\Framework\TestCase;

class DigestMD5MechanismTest extends TestCase
{
    /**
     * @var DigestMD5Mechanism
     */
    protected $mech;

    public function setUp()
    {
        $this->mech = new DigestMD5Mechanism();
    }

    public function testToString()
    {
        $this->assertEquals('DIGEST-MD5', (string) $this->mech);
    }

    public function testSecurityStrength()
    {
        $strength = $this->mech->securityStrength();

        $this->assertTrue($strength->supportsPrivacy());
        $this->assertTrue($strength->supportsIntegrity());
        $this->assertTrue($strength->supportsAuth());
        $this->assertFalse($strength->isPlainTextAuth());
        $this->assertEquals(128, $strength->maxKeySize());
    }

    public function testSecurity()
    {
        $this->assertInstanceOf(SecurityLayerInterface::class, $this->mech->securityLayer());
    }

    public function testChallenge()
    {
        $this->assertInstanceOf(ChallengeInterface::class, $this->mech->challenge());
    }

    public function testGetName()
    {
        $this->assertEquals('DIGEST-MD5', $this->mech->getName());
    }

    public function testComputeResponse()
    {
        $challenge = new Message([
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'realm' => 'huh-sys',
            'qop' => ['auth', 'auth-int', 'auth-conf',],
            'cipher' => ['rc4-40', 'rc4-56', 'rc4', 'des', '3des',],
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

        $this->assertEquals(
            '16c0ee7bfa5fcc3b2d19b50f17ebb8f2',
            DigestMD5Mechanism::computeResponse('Password1',$challenge, $response, false)
        );
    }

    public function testComputeA1()
    {
        $challenge = new Message([
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'realm' => 'huh-sys',
            'qop' => ['auth', 'auth-int', 'auth-conf',],
            'cipher' => ['rc4-40', 'rc4-56', 'rc4', 'des', '3des',],
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

        $this->assertEquals(
            'c951ca891eaedcf85e8c6c9d8763406d',
            DigestMD5Mechanism::computeA1('Password1',$challenge, $response)
        );
    }
}
