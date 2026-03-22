<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl\Encoder;

use FreeDSx\Sasl\Encoder\ScramEncoder;
use FreeDSx\Sasl\Exception\SaslEncodingException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

class ScramEncoderTest extends TestCase
{
    /**
     * @var ScramEncoder
     */
    private $encoder;

    /**
     * @var SaslContext
     */
    private $context;

    public function setUp(): void
    {
        parent::setUp();
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

        $this->assertSame(
            'n=user,r=fyko+d2lbbFgONRv9qkxdawL',
            $encoded
        );
    }

    public function testEncodePreservesBase64ValuesWithEqualSigns(): void
    {
        $message = new Message([
            'v' => 'rmF9pqV8S7suAoZWja4dJRkFsKQ=',
        ]);

        $this->assertSame(
            'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=',
            $this->encoder->encode($message, $this->context)
        );
    }

    public function testDecodeClientFirstMessageStripsGs2Header(): void
    {
        // n,, is the GS2 header for a standard (non-channel-binding) client-first-message
        $decoded = $this->encoder->decode('n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL', $this->context);

        $this->assertSame(
            'n,,',
            $decoded->get('gs2-header')
        );
        $this->assertSame(
            'user',
            $decoded->get('n')
        );
        $this->assertSame(
            'fyko+d2lbbFgONRv9qkxdawL',
            $decoded->get('r')
        );
    }

    public function testDecodeClientFirstMessageWithChannelBindingGs2Header(): void
    {
        $decoded = $this->encoder->decode('p=tls-unique,,n=user,r=clientnonce', $this->context);

        $this->assertSame(
            'p=tls-unique,,',
            $decoded->get('gs2-header')
        );
        $this->assertSame(
            'user',
            $decoded->get('n')
        );
        $this->assertSame(
            'clientnonce',
            $decoded->get('r')
        );
    }

    public function testDecodeClientFirstMessageWithYGs2Header(): void
    {
        $decoded = $this->encoder->decode('y,,n=user,r=clientnonce', $this->context);

        $this->assertSame(
            'y,,',
            $decoded->get('gs2-header')
        );
        $this->assertSame(
            'user',
            $decoded->get('n')
        );
    }

    public function testDecodeServerFirstMessage(): void
    {
        $decoded = $this->encoder->decode(
            'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096',
            $this->context
        );

        $this->assertSame(
            'fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j',
            $decoded->get('r')
        );
        $this->assertSame(
            'QSXCR+Q6sek8bf92',
            $decoded->get('s')
        );
        $this->assertSame(
            '4096',
            $decoded->get('i')
        );
        $this->assertNull($decoded->get('gs2-header'));
    }

    public function testDecodeClientFinalMessage(): void
    {
        $decoded = $this->encoder->decode(
            'c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=',
            $this->context
        );

        $this->assertSame(
            'biws',
            $decoded->get('c')
        );
        $this->assertSame(
            'fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j',
            $decoded->get('r')
        );
        $this->assertSame(
            'v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=',
            $decoded->get('p')
        );
    }

    public function testDecodeServerFinalMessage(): void
    {
        $decoded = $this->encoder->decode(
            'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=',
            $this->context
        );

        $this->assertSame(
            'rmF9pqV8S7suAoZWja4dJRkFsKQ=',
            $decoded->get('v')
        );
    }

    public function testDecodeThrowsOnMalformedAttributeWithNoEquals(): void
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->decode(
            'r=validnonce,malformed',
            $this->context
        );
    }

    public function testDecodeThrowsOnMandatoryExtension(): void
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->decode(
            'm=unsupported,r=nonce',
            $this->context
        );
    }
}
