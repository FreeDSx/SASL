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

namespace Tests\Unit\FreeDSx\Sasl;

use FreeDSx\Sasl\Exception\SaslBufferException;
use FreeDSx\Sasl\SaslBuffer;
use PHPUnit\Framework\TestCase;

final class SaslBufferTest extends TestCase
{
    public function testUnwrap(): void
    {
        self::assertSame('foo', SaslBuffer::unwrap((string) hex2bin('00000003666f6f')));
    }

    public function testWrap(): void
    {
        self::assertSame(hex2bin('00000003666f6f'), SaslBuffer::wrap('foo'));
    }

    public function testUnwrapOnlyRemovesTheSizeSpecified(): void
    {
        self::assertSame('foo', SaslBuffer::unwrap((string) hex2bin('00000003666f6f6f6f6f')));
    }

    public function testUnwrapThrowsIncompleteBufferWhenTheLengthIsTooSmall(): void
    {
        $this->expectException(SaslBufferException::class);

        SaslBuffer::unwrap('000000');
    }

    public function testUnwrapThrowsIncompleteBufferWhenTheDataIsIncomplete(): void
    {
        $this->expectException(SaslBufferException::class);

        SaslBuffer::unwrap('000000036f6f');
    }
}
