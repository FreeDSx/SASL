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

use PHPUnit\Framework\TestCase;
use FreeDSx\Sasl\SaslContext;

class SaslContextTest extends TestCase
{
    /**
     * @var SaslContext
     */
    protected $context;

    public function setUp()
    {
        $this->context = new SaslContext(['username' => 'foo']);
    }

    public function testHas()
    {
        $this->assertFalse($this->context->has('foo'));
        $this->assertTrue($this->context->has('username'));
    }

    public function testIsAuthenticated()
    {
        $this->assertFalse($this->context->isAuthenticated());
    }

    public function testIsServerMode()
    {
        $this->assertFalse($this->context->isServerMode());
    }

    public function testSetIsServerMode()
    {
        $this->context->setIsServerMode(true);

        $this->assertTrue($this->context->isServerMode());
    }

    public function testGetData()
    {
        $this->assertEquals(['username' => 'foo'], $this->context->getData());
    }

    public function testSetIsAuthenticated()
    {
        $this->context->setIsAuthenticated(true);

        $this->assertTrue($this->context->isAuthenticated());
    }

    public function testSet()
    {
        $this->context->set('foo', 'bar');

        $this->assertEquals('bar', $this->context->get('foo'));
    }

    public function testSetHasSecurityLayer()
    {
        $this->context->setHasSecurityLayer(true);

        $this->assertTrue($this->context->hasSecurityLayer());
    }

    public function testHasSecurityLayer()
    {
        $this->assertFalse($this->context->hasSecurityLayer());
    }

    public function testGet()
    {
        $this->assertEquals('foo', $this->context->get('username'));
    }

    public function testGetResponse()
    {
        $this->assertNull($this->context->getResponse());
    }

    public function testSetResponse()
    {
        $this->context->setResponse('foo');

        $this->assertEquals('foo', $this->context->getResponse());
    }
}
