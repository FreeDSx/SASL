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

namespace Tests\Unit\FreeDSx\Sasl\Encoder;

use FreeDSx\Sasl\Encoder\ScramEncoder;
use FreeDSx\Sasl\Exception\SaslEncodingException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

final class ScramEncoderTest extends TestCase
{
    private ScramEncoder $encoder;

    private SaslContext $context;

    protected function setUp(): void
    {
        $this->encoder = new ScramEncoder();
        $this->context = new SaslContext();
    }

    public function testEncodeProducesCommaSeparatedAttrValuePairs(): void
    {
        $message = new Message([
            'n' => 'user',
            'r' => 'fyko+d2lbbFgONRv9qkxdawL',
        ]);

        $encoded = $this->encoder->encode($message, $this->context);

        self::assertSame('n=user,r=fyko+d2lbbFgONRv9qkxdawL', $encoded);
    }

    public function testEncodePreservesBase64ValuesWithEqualSigns(): void
    {
        $message = new Message(['v' => 'rmF9pqV8S7suAoZWja4dJRkFsKQ=']);

        self::assertSame(
            'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=',
            $this->encoder->encode($message, $this->context),
        );
    }

    public function testDecodeClientFirstMessageStripsGs2Header(): void
    {
        $decoded = $this->encoder->decode('n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL', $this->context);

        self::assertSame('n,,', $decoded->get('gs2-header'));
        self::assertSame('user', $decoded->get('n'));
        self::assertSame('fyko+d2lbbFgONRv9qkxdawL', $decoded->get('r'));
    }

    public function testDecodeClientFirstMessageWithChannelBindingGs2Header(): void
    {
        $decoded = $this->encoder->decode('p=tls-unique,,n=user,r=clientnonce', $this->context);

        self::assertSame('p=tls-unique,,', $decoded->get('gs2-header'));
        self::assertSame('user', $decoded->get('n'));
        self::assertSame('clientnonce', $decoded->get('r'));
    }

    public function testDecodeClientFirstMessageWithAnAuthzIdInTheGs2Header(): void
    {
        $decoded = $this->encoder->decode(
            'n,a=admin,n=user,r=clientnonce',
            $this->context,
        );

        self::assertSame(
            'n,a=admin,',
            $decoded->get('gs2-header'),
        );
        self::assertSame(
            'admin',
            $decoded->get(SaslContext::AUTHZID),
        );
        self::assertSame(
            'user',
            $decoded->get('n'),
        );
        self::assertSame(
            'clientnonce',
            $decoded->get('r'),
        );
    }

    public function testDecodeClientFirstMessageWithoutAnAuthzIdHasNone(): void
    {
        $decoded = $this->encoder->decode(
            'n,,n=user,r=clientnonce',
            $this->context,
        );

        self::assertNull($decoded->get(SaslContext::AUTHZID));
    }

    public function testDecodeClientFirstMessageWithYGs2Header(): void
    {
        $decoded = $this->encoder->decode('y,,n=user,r=clientnonce', $this->context);

        self::assertSame('y,,', $decoded->get('gs2-header'));
        self::assertSame('user', $decoded->get('n'));
    }

    public function testDecodeServerFirstMessage(): void
    {
        $decoded = $this->encoder->decode(
            'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096',
            $this->context,
        );

        self::assertSame('fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j', $decoded->get('r'));
        self::assertSame('QSXCR+Q6sek8bf92', $decoded->get('s'));
        self::assertSame('4096', $decoded->get('i'));
        self::assertNull($decoded->get('gs2-header'));
    }

    public function testDecodeClientFinalMessage(): void
    {
        $decoded = $this->encoder->decode(
            'c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=',
            $this->context,
        );

        self::assertSame('biws', $decoded->get('c'));
        self::assertSame('fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j', $decoded->get('r'));
        self::assertSame('v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=', $decoded->get('p'));
    }

    public function testDecodeServerFinalMessage(): void
    {
        $decoded = $this->encoder->decode('v=rmF9pqV8S7suAoZWja4dJRkFsKQ=', $this->context);

        self::assertSame('rmF9pqV8S7suAoZWja4dJRkFsKQ=', $decoded->get('v'));
    }

    public function testDecodeThrowsOnMalformedAttributeWithNoEquals(): void
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->decode('r=validnonce,malformed', $this->context);
    }

    public function testDecodeThrowsOnMandatoryExtension(): void
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->decode('m=unsupported,r=nonce', $this->context);
    }
}
