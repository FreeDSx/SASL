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

use FreeDSx\Sasl\Encoder\PlainEncoder;
use FreeDSx\Sasl\Exception\SaslEncodingException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

class PlainEncoderTest extends TestCase
{
    /**
     * @var PlainEncoder
     */
    protected $encoder;

    /**
     * @var SaslContext
     */
    protected $context;

    public function setUp()
    {
        parent::setUp();
        $this->encoder = new PlainEncoder();
        $this->context = new SaslContext();
    }

    public function testItEncodes()
    {
        $result = $this->encoder->encode(
            new Message(['authzid' => 'foo', 'authcid' => 'foo', 'password' => 'bar']),
            $this->context
        );

        $this->assertEquals("foo\x00foo\x00bar", $result);
    }

    public function testItDecodes()
    {
        $result = $this->encoder->decode("foo1\x00foo2\x00bar", $this->context);

        $expected = [
            'authzid' => 'foo1',
            'authcid' => 'foo2',
            'password' => 'bar',
        ];
        $this->assertEquals($expected, $result->toArray());
    }

    public function testItValidatesTheDecodedMessage()
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->decode("fo\x00o1\x00foo2\x00bar", $this->context);
    }

    public function testItValidatesTheEncodedMessage()
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->encode(new Message(['authzid' => 'foo']), $this->context);
    }

    public function testItValidatesTheEncodedMessageHasNoNullCharacters()
    {
        $this->expectException(SaslEncodingException::class);

        $this->encoder->encode(new Message(['authzid' => "fo\x00o", 'authcid' => 'foo', 'password' => 'bar']), $this->context);
    }
}
