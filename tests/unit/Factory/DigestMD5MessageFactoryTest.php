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

namespace Tests\Unit\FreeDSx\Sasl\Factory;

use FreeDSx\Sasl\Encoder\DigestMD5Encoder;
use FreeDSx\Sasl\Factory\DigestMD5MessageFactory;
use FreeDSx\Sasl\Factory\DigestMD5MessageType;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

final class DigestMD5MessageFactoryTest extends TestCase
{
    private DigestMD5MessageFactory $factory;

    private DigestMD5Encoder $encoder;

    protected function setUp(): void
    {
        $this->factory = new DigestMD5MessageFactory();
        $this->encoder = new DigestMD5Encoder();
    }

    public function testCreateServerChallenge(): void
    {
        $challenge = $this->factory->create(
            DigestMD5MessageType::SERVER_CHALLENGE,
            ['use_integrity' => true, 'use_privacy' => true],
        );

        self::assertCount(7, $challenge->toArray());
        self::assertSame('md5-sess', $challenge->get('algorithm'));
        self::assertSame(['auth', 'auth-int', 'auth-conf'], $challenge->get('qop'));
        self::assertSame('65536', $challenge->get('maxbuf'));
        self::assertSame('utf-8', $challenge->get('charset'));
        self::assertNotEmpty($challenge->get('realm'), 'The realm value is empty.');
        self::assertNotEmpty($challenge->get('nonce'), 'The nonce value is empty.');
        self::assertNotEmpty($challenge->get('cipher'), 'The cipher value is empty.');
    }

    public function testCreateClientResponse(): void
    {
        $challenge = $this->encoder->decode(
            (string) hex2bin('6e6f6e63653d225a7a6b307578374b674f56506d4e37644c6f66476d394b714e6573626e43585263494151536d787551456b3d222c7265616c6d3d226875682d737973222c716f703d22617574682c617574682d696e742c617574682d636f6e66222c6369706865723d227263342d34302c7263342d35362c7263342c6465732c33646573222c6d61786275663d36353533362c636861727365743d7574662d382c616c676f726974686d3d6d64352d73657373'),
            new SaslContext(),
        );
        $response = $this->factory->create(
            DigestMD5MessageType::CLIENT_RESPONSE,
            ['service' => 'ldap'],
            $challenge,
        );

        self::assertCount(9, $response->toArray());
        self::assertSame('auth-conf', $response->get('qop'));
        $digestUri = $response->get('digest-uri');
        self::assertIsString($digestUri);
        self::assertStringStartsWith('ldap/huh-sys', $digestUri);
        self::assertSame(1, $response->get('nc'));
        self::assertSame('md5-sess', $response->get('algorithm'));
        self::assertNotEmpty($response->get('realm'), 'The realm value is empty.');
        self::assertNotEmpty($response->get('username'), 'The username value is empty.');
        self::assertNotEmpty($response->get('cnonce'), 'The cnonce value is empty.');
        self::assertNotEmpty($response->get('nonce'), 'The nonce value is empty.');
    }

    public function testCreateServerResponse(): void
    {
        $response = $this->factory->create(
            DigestMD5MessageType::SERVER_RESPONSE,
            ['rspauth' => 'foobar'],
        );

        self::assertEquals(new Message(['rspauth' => 'foobar']), $response);
    }
}
