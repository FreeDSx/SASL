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

use FreeDSx\Sasl\Encoder\AnonymousEncoder;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

class AnonymousEncoderTest extends TestCase
{
    /**
     * @var AnonymousEncoder
     */
    protected $encoder;

    /**
     * @var SaslContext
     */
    protected $context;

    public function setUp()
    {
        parent::setUp();
        $this->encoder = new AnonymousEncoder();
        $this->context = new SaslContext();
    }

    public function testItEncodes()
    {
        $result = $this->encoder->encode(
            new Message(['trace' => 'foo@bar.local']),
            $this->context
        );

        $this->assertEquals("foo@bar.local", $result);
    }

    public function testItDecodes()
    {
        $result = $this->encoder->decode("foo@bar.local", $this->context);

        $this->assertEquals(['trace' => 'foo@bar.local'], $result->toArray());
    }

    public function testItDecodesWithNoData()
    {
        $result = $this->encoder->decode('', $this->context);

        $this->assertEquals([], $result->toArray());
    }
}
