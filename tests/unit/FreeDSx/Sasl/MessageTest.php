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

use FreeDSx\Sasl\Message;
use PHPUnit\Framework\TestCase;

class MessageTest extends TestCase
{
    /**
     * @var Message
     */
    protected $message;

    public function setUp()
    {
        $this->message = new Message(['foo' => 'bar', 'bar' => 'foo']);
    }

    public function testSet()
    {
        $this->message->set('name', 'test');

        $this->assertEquals('test', $this->message->get('name'));
    }

    public function testGet()
    {
        $this->assertEquals('bar', $this->message->get('foo'));
    }

    public function testCount()
    {
        $this->assertEquals(2, $this->message->count());
    }

    public function testHas()
    {
        $this->assertEquals(true, $this->message->has('foo'));
        $this->assertEquals(false, $this->message->has('nothing'));
    }

    public function testToArray()
    {
        $this->assertEquals([
            'foo' => 'bar',
            'bar' => 'foo'
        ], $this->message->toArray());
    }
}
