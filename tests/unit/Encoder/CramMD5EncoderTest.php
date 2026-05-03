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

use FreeDSx\Sasl\Encoder\CramMD5Encoder;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

final class CramMD5EncoderTest extends TestCase
{
    private CramMD5Encoder $encoder;

    private SaslContext $context;

    protected function setUp(): void
    {
        $this->encoder = new CramMD5Encoder();
        $this->context = new SaslContext();
    }

    public function testEncodeClientResponse(): void
    {
        $digest = hash_hmac('md5', 'foo', 'bar');

        $response = $this->encoder->encode(
            new Message(['username' => 'foo', 'digest' => $digest]),
            $this->context,
        );

        self::assertSame('foo 31b6db9e5eb4addb42f1a6ca07367adc', $response);
    }

    public function testEncodeServerChallenge(): void
    {
        $this->context->setIsServerMode(true);
        $response = $this->encoder->encode(new Message(['challenge' => 'foobar']), $this->context);

        self::assertSame('<foobar>', $response);
    }

    public function testDecodeServerChallenge(): void
    {
        $response = $this->encoder->decode('<foobar>', $this->context);

        self::assertSame(['challenge' => '<foobar>'], $response->toArray());
    }

    public function testDecodeClientChallenge(): void
    {
        $this->context->setIsServerMode(true);
        $response = $this->encoder->decode('foo 31b6db9e5eb4addb42f1a6ca07367adc', $this->context);

        self::assertSame(
            ['username' => 'foo', 'digest' => '31b6db9e5eb4addb42f1a6ca07367adc'],
            $response->toArray(),
        );
    }
}
