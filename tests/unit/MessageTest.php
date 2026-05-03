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

use FreeDSx\Sasl\Message;
use PHPUnit\Framework\TestCase;

final class MessageTest extends TestCase
{
    private Message $message;

    protected function setUp(): void
    {
        $this->message = new Message(['foo' => 'bar', 'bar' => 'foo']);
    }

    public function testSet(): void
    {
        $this->message->set('name', 'test');

        self::assertSame('test', $this->message->get('name'));
    }

    public function testGet(): void
    {
        self::assertSame('bar', $this->message->get('foo'));
    }

    public function testCount(): void
    {
        self::assertCount(2, $this->message);
    }

    public function testHas(): void
    {
        self::assertTrue($this->message->has('foo'));
        self::assertFalse($this->message->has('nothing'));
    }

    public function testToArray(): void
    {
        self::assertSame([
            'foo' => 'bar',
            'bar' => 'foo',
        ], $this->message->toArray());
    }
}
