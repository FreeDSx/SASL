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

use FreeDSx\Sasl\Encoder\AnonymousEncoder;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

final class AnonymousEncoderTest extends TestCase
{
    private AnonymousEncoder $encoder;

    private SaslContext $context;

    protected function setUp(): void
    {
        $this->encoder = new AnonymousEncoder();
        $this->context = new SaslContext();
    }

    public function testItEncodes(): void
    {
        $result = $this->encoder->encode(
            new Message(['trace' => 'foo@bar.local']),
            $this->context,
        );

        self::assertSame('foo@bar.local', $result);
    }

    public function testItDecodes(): void
    {
        $result = $this->encoder->decode('foo@bar.local', $this->context);

        self::assertSame(['trace' => 'foo@bar.local'], $result->toArray());
    }

    public function testItDecodesWithNoData(): void
    {
        $result = $this->encoder->decode('', $this->context);

        self::assertSame([], $result->toArray());
    }
}
