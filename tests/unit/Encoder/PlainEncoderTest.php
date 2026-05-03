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

use FreeDSx\Sasl\Encoder\PlainEncoder;
use FreeDSx\Sasl\Exception\SaslEncodingException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

final class PlainEncoderTest extends TestCase
{
    private PlainEncoder $encoder;

    private SaslContext $context;

    protected function setUp(): void
    {
        $this->encoder = new PlainEncoder();
        $this->context = new SaslContext();
    }

    public function testItEncodes(): void
    {
        $result = $this->encoder->encode(
            new Message(['authzid' => 'foo', 'authcid' => 'foo', 'password' => 'bar']),
            $this->context,
        );

        self::assertSame("foo\x00foo\x00bar", $result);
    }

    public function testItDecodes(): void
    {
        $result = $this->encoder->decode("foo1\x00foo2\x00bar", $this->context);

        self::assertSame(
            ['authzid' => 'foo1', 'authcid' => 'foo2', 'password' => 'bar'],
            $result->toArray(),
        );
    }

    public function testItValidatesTheDecodedMessage(): void
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->decode("fo\x00o1\x00foo2\x00bar", $this->context);
    }

    public function testItValidatesTheEncodedMessage(): void
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->encode(new Message(['authzid' => 'foo']), $this->context);
    }

    public function testItValidatesTheEncodedMessageHasNoNullCharacters(): void
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->encode(
            new Message(['authzid' => "fo\x00o", 'authcid' => 'foo', 'password' => 'bar']),
            $this->context,
        );
    }
}
