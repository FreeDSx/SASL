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

use FreeDSx\Sasl\Encoder\CramMD5Encoder;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

class CramMD5EncoderTest extends TestCase
{
    /**
     * @var CramMD5Encoder
     */
    protected $encoder;

    /**
     * @var SaslContext
     */
    protected $context;

    public function setUp()
    {
        parent::setUp();
        $this->encoder = new CramMD5Encoder();
        $this->context = new SaslContext();
    }

    public function testEncodeClientResponse()
    {
        $digest = hash_hmac('md5', 'foo', 'bar');

        $response = $this->encoder->encode(
            new Message(['username' => 'foo', 'digest' => $digest]),
            $this->context
        );
        $this->assertEquals('foo 31b6db9e5eb4addb42f1a6ca07367adc', $response);
    }

    public function testEncodeServerChallenge()
    {
        $this->context->setIsServerMode(true);
        $response = $this->encoder->encode(new Message(['challenge' => 'foobar']), $this->context);

        $this->assertEquals('<foobar>', $response);
    }

    public function testDecodeServerChallenge()
    {
        $response = $this->encoder->decode('<foobar>', $this->context);

        $this->assertEquals(['challenge' => '<foobar>'], $response->toArray());
    }

    public function testDecodeClientChallenge()
    {
        $this->context->setIsServerMode(true);
        $response = $this->encoder->decode('foo 31b6db9e5eb4addb42f1a6ca07367adc', $this->context);

        $this->assertEquals(['username' => 'foo', 'digest' => '31b6db9e5eb4addb42f1a6ca07367adc'], $response->toArray());
    }
}
