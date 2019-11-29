<?php
/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl;

use FreeDSx\Sasl\Exception\SaslBufferException;
use FreeDSx\Sasl\SaslBuffer;
use PHPUnit\Framework\TestCase;

class SaslBufferTest extends TestCase
{
    public function testUnwrap()
    {
        $this->assertEquals(SaslBuffer::unwrap(hex2bin('00000003666f6f')), 'foo');
    }

    public function testWrap()
    {
        $this->assertEquals(SaslBuffer::wrap('foo'), hex2bin('00000003666f6f'));
    }

    public function testUnwrapOnlyRemovesTheSizeSpecified()
    {
        $this->assertEquals(SaslBuffer::unwrap(hex2bin('00000003666f6f6f6f6f')), 'foo');
    }

    public function testUnwrapThrowsIncompleteBufferWhenTheLengthIsTooSmall()
    {
        $this->expectException(SaslBufferException::class);

        SaslBuffer::unwrap('000000');
    }

    public function testUnwrapThrowsIncompleteBufferWhenTheDataIsIncomplete()
    {
        $this->expectException(SaslBufferException::class);

        SaslBuffer::unwrap('000000036f6f');
    }
}
