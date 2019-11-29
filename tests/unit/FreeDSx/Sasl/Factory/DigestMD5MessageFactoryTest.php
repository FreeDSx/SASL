<?php
/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl\Factory;

use FreeDSx\Sasl\Encoder\DigestMD5Encoder;
use FreeDSx\Sasl\Factory\DigestMD5MessageFactory;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

class DigestMD5MessageFactoryTest extends TestCase
{
    protected $factory;

    protected $encoder;

    public function setUp()
    {
        $this->factory = new DigestMD5MessageFactory();
        $this->encoder = new DigestMD5Encoder();
    }

    public function testCreateServerChallenge()
    {
        $challenge = $this->factory->create(
            DigestMD5MessageFactory::MESSAGE_SERVER_CHALLENGE, ['use_integrity' => true, 'use_privacy' => true]
        );

        $this->assertCount(7, $challenge->toArray());
        $this->assertEquals('md5-sess', $challenge->get('algorithm'));
        $this->assertEquals(['auth', 'auth-int', 'auth-conf'], $challenge->get('qop'));
        $this->assertEquals('65536', $challenge->get('maxbuf'));
        $this->assertEquals('utf-8', $challenge->get('charset'));
        $this->assertNotEmpty($challenge->get('realm'), 'The realm value is empty.');
        $this->assertNotEmpty($challenge->get('nonce'), 'The nonce value is empty.');
        $this->assertNotEmpty($challenge->get('cipher'), 'The cipher value is empty.');
    }

    public function testCreateClientResponse()
    {
        $challenge = $this->encoder->decode(hex2bin('6e6f6e63653d225a7a6b307578374b674f56506d4e37644c6f66476d394b714e6573626e43585263494151536d787551456b3d222c7265616c6d3d226875682d737973222c716f703d22617574682c617574682d696e742c617574682d636f6e66222c6369706865723d227263342d34302c7263342d35362c7263342c6465732c33646573222c6d61786275663d36353533362c636861727365743d7574662d382c616c676f726974686d3d6d64352d73657373'), new SaslContext());
        $response = $this->factory->create(DigestMD5MessageFactory::MESSAGE_CLIENT_RESPONSE, ['service' => 'ldap'], $challenge);

        $this->assertCount(9, $response->toArray());
        $this->assertEquals('auth-conf', $response->get('qop'));
        $this->assertStringStartsWith('ldap/huh-sys', $response->get('digest-uri'));
        $this->assertEquals("00000001", $response->get('nc'));
        $this->assertEquals("md5-sess", $response->get('algorithm'));
        $this->assertNotEmpty($response->get('realm'), 'The realm value is empty.');
        $this->assertNotEmpty($response->get('username'), 'The username value is empty.');
        $this->assertNotEmpty($response->get('cnonce'), 'The cnonce value is empty.');
        $this->assertNotEmpty($response->get('nonce'), 'The nonce value is empty.');
    }

    public function testCreateServerResponse()
    {
        $response = $this->factory->create(DigestMD5MessageFactory::MESSAGE_SERVER_RESPONSE, ['rspauth' => 'foobar']);

        $this->assertEquals($response, new Message(['rspauth' => 'foobar']));
    }
}
