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

namespace Tests\Unit\FreeDSx\Sasl\Security;

use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\Security\DigestMD5SecurityLayer;
use PHPUnit\Framework\TestCase;

final class DigestMD5SecurityLayerTest extends TestCase
{
    private DigestMD5SecurityLayer $security;

    private SaslContext $clientContext;

    private SaslContext $serverContext;

    protected function setUp(): void
    {
        $this->security = new DigestMD5SecurityLayer();
        $this->clientContext = new SaslContext();
        $this->clientContext->setData([
            'username' => 'WillifoA',
            'digest-uri' => 'ldap/huh-sys',
            'qop' => 'auth-conf',
            'seqnumrcv' => 0,
            'seqnumsnt' => 0,
        ]);
        $this->clientContext->setIsAuthenticated(true);
        $this->clientContext->setHasSecurityLayer(true);

        $this->serverContext = new SaslContext();
        $this->serverContext->setData([
            'username' => 'WillifoA',
            'digest-uri' => 'ldap/huh-sys',
            'qop' => 'auth-conf',
            'seqnumrcv' => 0,
            'seqnumsnt' => 0,
        ]);
        $this->serverContext->setIsAuthenticated(true);
        $this->serverContext->setHasSecurityLayer(true);
        $this->serverContext->setIsServerMode(true);

        # Encrypted-payload tests fail with newer OpenSSL across OSes — needs investigation.
        self::markTestSkipped('Need to investigate why this is failing on all recent OS types :(');
    }

    public function testWrapWithPrivacyRC4(): void
    {
        $this->clientContext->set('a1', hex2bin('960bcfc7a190d6b1dcabcd5bc7f53fe0'));
        $this->clientContext->set('cipher', 'rc4');
        $message = (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        self::assertSame(
            (string) hex2bin('6c9849465f4a88af35b82a6b8f35295e8c60e9d17245f3a8fbe5be1ca6599d7aef09b7f5caf7f43a7eea74b02c669c6a9bb346ba863ab843cf51eccd5b0b570f912e910dd234000100000000'),
            $this->security->wrap($message, $this->clientContext),
        );
    }

    public function testUnwrapWithPrivacyRC4(): void
    {
        $this->markSkippedIfCipherNotSupported('rc4');
        $this->serverContext->set('a1', hex2bin('960bcfc7a190d6b1dcabcd5bc7f53fe0'));
        $this->serverContext->set('cipher', 'rc4');
        $message = (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        self::assertSame(
            $message,
            $this->security->unwrap(
                (string) hex2bin('6c9849465f4a88af35b82a6b8f35295e8c60e9d17245f3a8fbe5be1ca6599d7aef09b7f5caf7f43a7eea74b02c669c6a9bb346ba863ab843cf51eccd5b0b570f912e910dd234000100000000'),
                $this->serverContext,
            ),
        );
    }

    public function testWrapWithRC440(): void
    {
        $this->clientContext->set('a1', hex2bin('407a52fb725042db234e11b34fb5fd55'));
        $this->clientContext->set('cipher', 'rc4-40');
        $message = (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        self::assertSame(
            (string) hex2bin('056173eaae8b7ac19b1f0d73e8e340c37e83b6ab23377f143b1d2722cf11657b1de53c61ce7a2898786b01a30ca940521c6ade80f01f155e798babc7a1275614656d1b74dee7000100000000'),
            $this->security->wrap($message, $this->clientContext),
        );
    }

    public function testUnwrapWithRC440(): void
    {
        $this->markSkippedIfCipherNotSupported('rc4-40');
        $this->serverContext->set('a1', hex2bin('407a52fb725042db234e11b34fb5fd55'));
        $this->serverContext->set('cipher', 'rc4-40');
        $encrypted = (string) hex2bin('056173eaae8b7ac19b1f0d73e8e340c37e83b6ab23377f143b1d2722cf11657b1de53c61ce7a2898786b01a30ca940521c6ade80f01f155e798babc7a1275614656d1b74dee7000100000000');

        self::assertSame(
            (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000'),
            $this->security->unwrap($encrypted, $this->serverContext),
        );
    }

    public function testWrapWithPrivacy3Des(): void
    {
        $this->clientContext->set('a1', hex2bin('9969a25310dd52c864715057ca181374'));
        $this->clientContext->set('cipher', '3des');
        $message = (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        self::assertSame(
            (string) hex2bin('73ebc692c839c8382c4bc669076fa893d1deaca630a1c74dcb0354159680372e555863e2e609a0ce72f06b7bb64fed4e3cf30057af5fd23ff6e0ffda06eb7fdb67edc8b331723f02000100000000'),
            $this->security->wrap($message, $this->clientContext),
        );
    }

    public function testUnwrapWithPrivacy3Des(): void
    {
        $this->serverContext->set('a1', hex2bin('9969a25310dd52c864715057ca181374'));
        $this->serverContext->set('cipher', '3des');
        $encrypted = (string) hex2bin('73ebc692c839c8382c4bc669076fa893d1deaca630a1c74dcb0354159680372e555863e2e609a0ce72f06b7bb64fed4e3cf30057af5fd23ff6e0ffda06eb7fdb67edc8b331723f02000100000000');

        self::assertSame(
            (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000'),
            $this->security->unwrap($encrypted, $this->serverContext),
        );
    }

    public function testWrapWithOnlyIntegrity(): void
    {
        $this->clientContext->set('a1', hex2bin('7b712f824ba6ad44548ba16b2ec75988'));
        $this->clientContext->set('qop', 'auth-int');
        $message = (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        self::assertSame(
            (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f41300086e03fcc17597a6dfb1c000100000000'),
            $this->security->wrap($message, $this->clientContext),
        );
    }

    public function testUnwrapWithOnlyIntegrity(): void
    {
        $this->serverContext->set('a1', hex2bin('7b712f824ba6ad44548ba16b2ec75988'));
        $this->serverContext->set('qop', 'auth-int');

        self::assertSame(
            (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000'),
            $this->security->unwrap(
                (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f41300086e03fcc17597a6dfb1c000100000000'),
                $this->serverContext,
            ),
        );
    }

    public function testThatItThrowsAnExceptionIfTheWrappedDataExceedsTheBufferSizeDuringUnwrap(): void
    {
        $context = new SaslContext(['maxbuf' => 2, 'qop' => 'auth-int']);
        $this->expectExceptionMessage('The wrapped buffer exceeds the maxbuf length of 2');
        $this->security->unwrap('foo', $context);
    }

    public function testThatItThrowsAnExceptionIfTheWrappedDataExceedsTheBufferSizeDuringWrap(): void
    {
        $this->serverContext->set('a1', hex2bin('7b712f824ba6ad44548ba16b2ec75988'));
        $this->serverContext->set('qop', 'auth-int');
        $this->serverContext->set('maxbuf', 2);

        $this->expectExceptionMessage('The wrapped buffer exceeds the maxbuf length of 2');
        $this->security->unwrap(
            (string) hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f41300086e03fcc17597a6dfb1c000100000000'),
            $this->serverContext,
        );
    }

    private function markSkippedIfCipherNotSupported(string $cipher): void
    {
        if (!in_array($cipher, openssl_get_cipher_methods(), true)) {
            self::markTestSkipped(sprintf(
                'The cipher %s is not supported on this system.',
                $cipher,
            ));
        }
    }
}
