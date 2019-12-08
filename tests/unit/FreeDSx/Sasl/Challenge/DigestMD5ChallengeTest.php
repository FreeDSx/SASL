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

use FreeDSx\Sasl\Challenge\DigestMD5Challenge;
use FreeDSx\Sasl\Encoder\DigestMD5Encoder;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

class DigestMD5ChallengeTest extends TestCase
{
    /**
     * @var DigestMD5Challenge
     */
    protected $challenge;

    /**
     * @var DigestMD5Encoder
     */
    protected $encoder;

    /**
     * @var string
     */
    protected $challengeData;

    /**
     * @var string
     */
    protected $responseData;

    /**
     * @var string
     */
    protected $rspAuthData;

    /**
     * @var string
     */
    protected $rspAuthSuccess;

    public function setUp()
    {
        $this->challenge = new DigestMD5Challenge();
        $this->encoder = new DigestMD5Encoder();
        $this->challengeData = hex2bin('6e6f6e63653d225a7a6b307578374b674f56506d4e37644c6f66476d394b714e6573626e43585263494151536d787551456b3d222c7265616c6d3d226875682d737973222c716f703d22617574682c617574682d696e742c617574682d636f6e66222c6369706865723d227263342d34302c7263342d35362c7263342c6465732c33646573222c6d61786275663d36353533362c636861727365743d7574662d382c616c676f726974686d3d6d64352d73657373');
        $this->responseData = hex2bin('757365726e616d653d2257696c6c69666f41222c6469676573742d7572693d226c6461702f6875682d737973222c716f703d617574682d636f6e662c6369706865723d7263342c616c676f726974686d3d6d64352d736573732c6e6f6e63653d225a7a6b307578374b674f56506d4e37644c6f66476d394b714e6573626e43585263494151536d787551456b3d222c636e6f6e63653d22745176425075444f4d54453d222c6e633d30303030303030312c7265616c6d3d226875682d737973222c726573706f6e73653d6439363436333039326565323462616466666261663531386331343934306430');
        $this->rspAuthData = hex2bin('727370617574683d3333323832383833643136316261376337656631616166633337666162393438');
        $this->rspAuthSuccess = hex2bin('727370617574683d3333323832383833643136316261376337656631616166633337666162393438');
    }

    public function testThatClientResponseIsGeneratedFromChallenge()
    {
        $response = $this->encoder->decode(
            $this->challenge->challenge($this->challengeData, ['use_privacy' => true])->getResponse(),
            (new SaslContext())->setIsServerMode(true)
        );

        $this->assertEquals('auth-conf', $response->get('qop'));
        $this->assertNotEmpty($response->get('response'), 'The response value is empty.');
    }

    public function testThatClientResponseUsesSpecificHostForDigestUriIfRequested()
    {
        $response = $this->encoder->decode(
            $this->challenge->challenge($this->challengeData, ['use_privacy' => true, 'host' => 'foo.bar.local'])->getResponse(),
            (new SaslContext())->setIsServerMode(true)
        );

        $this->assertEquals('ldap/foo.bar.local', $response->get('digest-uri'));
    }

    public function testSecurityLayerIsInitializedProperlyInTheContext()
    {
        $options = [
            'use_privacy' => true,
            'cipher' => 'rc4',
            'username' => 'WillifoA',
            'password' => 'Password1',
        ];
        $this->challenge->challenge($this->challengeData, ['cnonce' => 'tQvBPuDOMTE=', 'nonce' => 'Zzk0ux7KgOVPmN7dLofGm9KqNesbnCXRcIAQSmxuQEk='] + $options);
        $context = $this->challenge->challenge($this->rspAuthSuccess, ['cnonce' => 'tQvBPuDOMTE=', 'nonce' => 'Zzk0ux7KgOVPmN7dLofGm9KqNesbnCXRcIAQSmxuQEk='] + $options);

        $this->assertTrue($context->isAuthenticated(), 'Context should be authenticated, but was not.');
        $this->assertTrue($context->hasSecurityLayer(), 'Context should have a security layer, but it does not.');
        $this->assertEquals(0, $context->get('seqnumsnt'));
        $this->assertEquals(0, $context->get('seqnumrcv'));
    }

    public function testVerificationIsDoneOnTheServerResponse()
    {
        $this->challenge->challenge($this->challengeData);
        $context = $this->challenge->challenge($this->rspAuthData);

        $this->assertFalse($context->isAuthenticated());
        $this->assertFalse($context->hasSecurityLayer());
    }

    public function testAnExceptionIsThrownIfTheRspauthIsReceivedOutOfOrder()
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge($this->rspAuthData);
    }

    public function testGenerateServerChallengeForClientInServerMode()
    {
        $options = [
            'use_integrity' => true,
            'use_privacy' => true,
        ];
        $this->challenge = new DigestMD5Challenge(true);
        $challenge = $this->encoder->decode($this->challenge->challenge(null, $options)->getResponse(), new SaslContext());

        $this->assertEquals(['auth', 'auth-int', 'auth-conf'], $challenge->get('qop'));
        $this->assertNotEmpty($challenge->get('cipher'), 'The realm value is empty.');
        $this->assertNotEmpty($challenge->get('nonce'), 'The nonce must be generated.');
    }

    public function testGenerateServerResponseToClientResponse()
    {
        $options = [
            'use_integrity' => true,
            'use_privacy' => true,
        ];
        $this->challenge = new DigestMD5Challenge(true);
        $this->challenge->challenge(null, [
            'nonce' => 'Zzk0ux7KgOVPmN7dLofGm9KqNesbnCXRcIAQSmxuQEk=',
            'realm' => 'huh-sys',
        ] + $options);
        $response = $this->encoder->decode(
            $this->challenge->challenge($this->responseData, ['password' => 'Password1'] + $options)->getResponse(),
            (new SaslContext())->setIsServerMode(true)
        );

        $this->assertCount(1, $response->toArray());
        $this->assertEquals('33282883d161ba7c7ef1aafc37fab948', $response->get('rspauth'));
    }

    public function testIsCompleteIsNotTrueUntilTheRspauthIsProcessed()
    {
        $context = $this->challenge->challenge($this->challengeData);
        $this->assertFalse($context->isComplete());

        $context = $this->challenge->challenge($this->rspAuthData);
        $this->assertTrue($context->isComplete());
    }
}
