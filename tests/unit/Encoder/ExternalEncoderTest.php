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

use FreeDSx\Sasl\Encoder\ExternalEncoder;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

final class ExternalEncoderTest extends TestCase
{
    private ExternalEncoder $encoder;

    private SaslContext $context;

    protected function setUp(): void
    {
        $this->encoder = new ExternalEncoder();
        $this->context = new SaslContext();
    }

    public function testItEncodes(): void
    {
        $result = $this->encoder->encode(
            new Message(['authzid' => 'dn:cn=foo']),
            $this->context,
        );

        self::assertSame('dn:cn=foo', $result);
    }

    public function testItEncodesWithNoAuthzId(): void
    {
        $result = $this->encoder->encode(
            new Message(),
            $this->context,
        );

        self::assertSame('', $result);
    }

    public function testItDecodes(): void
    {
        $result = $this->encoder->decode('dn:cn=foo', $this->context);

        self::assertSame(['authzid' => 'dn:cn=foo'], $result->toArray());
    }

    public function testItDecodesWithNoData(): void
    {
        $result = $this->encoder->decode('', $this->context);

        self::assertSame([], $result->toArray());
    }
}
