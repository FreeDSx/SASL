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

use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

final class SaslContextTest extends TestCase
{
    private SaslContext $context;

    protected function setUp(): void
    {
        $this->context = new SaslContext(['username' => 'foo']);
    }

    public function testHas(): void
    {
        self::assertFalse($this->context->has('foo'));
        self::assertTrue($this->context->has('username'));
    }

    public function testIsAuthenticated(): void
    {
        self::assertFalse($this->context->isAuthenticated());
    }

    public function testIsServerMode(): void
    {
        self::assertFalse($this->context->isServerMode());
    }

    public function testSetIsServerMode(): void
    {
        $this->context->setIsServerMode(true);

        self::assertTrue($this->context->isServerMode());
    }

    public function testGetData(): void
    {
        self::assertSame(['username' => 'foo'], $this->context->getData());
    }

    public function testSetIsAuthenticated(): void
    {
        $this->context->setIsAuthenticated(true);

        self::assertTrue($this->context->isAuthenticated());
    }

    public function testSet(): void
    {
        $this->context->set('foo', 'bar');

        self::assertSame('bar', $this->context->get('foo'));
    }

    public function testSetHasSecurityLayer(): void
    {
        $this->context->setHasSecurityLayer(true);

        self::assertTrue($this->context->hasSecurityLayer());
    }

    public function testHasSecurityLayer(): void
    {
        self::assertFalse($this->context->hasSecurityLayer());
    }

    public function testGet(): void
    {
        self::assertSame('foo', $this->context->get('username'));
    }

    public function testGetResponse(): void
    {
        self::assertNull($this->context->getResponse());
    }

    public function testSetResponse(): void
    {
        $this->context->setResponse('foo');

        self::assertSame('foo', $this->context->getResponse());
    }
}
