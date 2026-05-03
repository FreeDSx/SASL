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

use FreeDSx\Sasl\Challenge\DigestMD5Challenge;
use FreeDSx\Sasl\Encoder\DigestMD5Encoder;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

final class DigestMD5ChallengeTest extends TestCase
{
    private DigestMD5Challenge $challenge;

    private DigestMD5Encoder $encoder;

    private string $challengeData;

    private string $rspAuthData;

    private string $rspAuthSuccess;

    protected function setUp(): void
    {
        $this->challenge = new DigestMD5Challenge();
        $this->encoder = new DigestMD5Encoder();
        $this->challengeData = (string) hex2bin('6e6f6e63653d225a7a6b307578374b674f56506d4e37644c6f66476d394b714e6573626e43585263494151536d787551456b3d222c7265616c6d3d226875682d737973222c716f703d22617574682c617574682d696e742c617574682d636f6e66222c6369706865723d227263342d34302c7263342d35362c7263342c6465732c33646573222c6d61786275663d36353533362c636861727365743d7574662d382c616c676f726974686d3d6d64352d73657373');
        $this->rspAuthData = (string) hex2bin('727370617574683d3333323832383833643136316261376337656631616166633337666162393438');
        $this->rspAuthSuccess = (string) hex2bin('727370617574683d3333323832383833643136316261376337656631616166633337666162393438');
    }

    public function testThatClientResponseIsGeneratedFromChallenge(): void
    {
        $response = $this->encoder->decode(
            (string) $this->challenge->challenge($this->challengeData, ['use_privacy' => true])->getResponse(),
            (new SaslContext())->setIsServerMode(true),
        );

        self::assertSame('auth-conf', $response->get('qop'));
        self::assertNotEmpty($response->get('response'), 'The response value is empty.');
    }

    public function testThatClientResponseUsesSpecificHostForDigestUriIfRequested(): void
    {
        $response = $this->encoder->decode(
            (string) $this->challenge->challenge(
                $this->challengeData,
                ['use_privacy' => true, 'host' => 'foo.bar.local'],
            )->getResponse(),
            (new SaslContext())->setIsServerMode(true),
        );

        self::assertSame('ldap/foo.bar.local', $response->get('digest-uri'));
    }

    public function testSecurityLayerIsInitializedProperlyInTheContext(): void
    {
        $options = [
            'use_privacy' => true,
            'cipher' => 'rc4',
            'username' => 'WillifoA',
            'password' => 'Password1',
        ];
        $this->challenge->challenge(
            $this->challengeData,
            ['cnonce' => 'tQvBPuDOMTE=', 'nonce' => 'Zzk0ux7KgOVPmN7dLofGm9KqNesbnCXRcIAQSmxuQEk='] + $options,
        );
        $context = $this->challenge->challenge(
            $this->rspAuthSuccess,
            ['cnonce' => 'tQvBPuDOMTE=', 'nonce' => 'Zzk0ux7KgOVPmN7dLofGm9KqNesbnCXRcIAQSmxuQEk='] + $options,
        );

        self::assertTrue($context->isAuthenticated(), 'Context should be authenticated, but was not.');
        self::assertTrue($context->hasSecurityLayer(), 'Context should have a security layer, but it does not.');
        self::assertSame(0, $context->get('seqnumsnt'));
        self::assertSame(0, $context->get('seqnumrcv'));
    }

    public function testVerificationIsDoneOnTheServerResponse(): void
    {
        $this->challenge->challenge($this->challengeData);
        $context = $this->challenge->challenge($this->rspAuthData);

        self::assertFalse($context->isAuthenticated());
        self::assertFalse($context->hasSecurityLayer());
    }

    public function testAnExceptionIsThrownIfTheRspauthIsReceivedOutOfOrder(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge($this->rspAuthData);
    }

    public function testGenerateServerChallengeForClientInServerMode(): void
    {
        $serverChallenge = new DigestMD5Challenge(true);
        $challenge = $this->encoder->decode(
            (string) $serverChallenge->challenge(null, ['use_integrity' => true, 'use_privacy' => true])->getResponse(),
            new SaslContext(),
        );

        self::assertSame(['auth', 'auth-int', 'auth-conf'], $challenge->get('qop'));
        self::assertNotEmpty($challenge->get('cipher'), 'The cipher value is empty.');
        self::assertNotEmpty($challenge->get('nonce'), 'The nonce must be generated.');
    }

    public function testGenerateServerResponseToClientResponse(): void
    {
        self::markTestSkipped('Test does not work on newer PHP due to deprecated ciphers it seems. Needs investigation.');
    }

    public function testIsCompleteIsNotTrueUntilTheRspauthIsProcessed(): void
    {
        $context = $this->challenge->challenge($this->challengeData);
        self::assertFalse($context->isComplete());

        $context = $this->challenge->challenge($this->rspAuthData);
        self::assertTrue($context->isComplete());
    }
}
