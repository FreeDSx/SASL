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

use FreeDSx\Sasl\Encoder\DigestMD5Encoder;
use FreeDSx\Sasl\Exception\SaslEncodingException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\TestCase;

final class DigestMD5EncoderTest extends TestCase
{
    private DigestMD5Encoder $encoder;

    protected function setUp(): void
    {
        $this->encoder = new DigestMD5Encoder();
    }

    public function testDecodeServerChallenge(): void
    {
        $challenge = $this->encoder->decode(
            (string) hex2bin('6e6f6e63653d226949414951483035755176705a6d6d3258522b696833644456337a7554696478744d4f33507346475253493d222c7265616c6d3d226875682d737973222c716f703d22617574682c617574682d696e742c617574682d636f6e66222c6369706865723d227263342d34302c7263342d35362c7263342c6465732c33646573222c6d61786275663d36353533362c636861727365743d7574662d382c616c676f726974686d3d6d64352d73657373'),
            new SaslContext(),
        );

        self::assertEquals(new Message([
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'realm' => 'huh-sys',
            'qop' => ['auth', 'auth-int', 'auth-conf'],
            'cipher' => ['rc4-40', 'rc4-56', 'rc4', 'des', '3des'],
            'maxbuf' => '65536',
            'charset' => 'utf-8',
            'algorithm' => 'md5-sess',
        ]), $challenge);
    }

    public function testDecodeClientResponse(): void
    {
        $response = $this->encoder->decode(
            (string) hex2bin('757365726e616d653d2257696c6c69666f41222c7265616c6d3d226875682d737973222c6e6f6e63653d226949414951483035755176705a6d6d3258522b696833644456337a7554696478744d4f33507346475253493d222c636e6f6e63653d226a536f346c6f4c38575772486f353042496d73716a5352424b4d416f58444458726a4e4743665932762b513d222c6e633d30303030303030312c716f703d617574682d636f6e662c6369706865723d7263342c6d61786275663d31363737373231352c6469676573742d7572693d226c6461702f6875682d737973222c726573706f6e73653d3136633065653762666135666363336232643139623530663137656262386632'),
            (new SaslContext())->setIsServerMode(true),
        );

        self::assertEquals(new Message([
            'username' => 'WillifoA',
            'realm' => 'huh-sys',
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'cnonce' => 'jSo4loL8WWrHo50BImsqjSRBKMAoXDDXrjNGCfY2v+Q=',
            'nc' => '00000001',
            'qop' => 'auth-conf',
            'cipher' => 'rc4',
            'maxbuf' => '16777215',
            'digest-uri' => 'ldap/huh-sys',
            'response' => '16c0ee7bfa5fcc3b2d19b50f17ebb8f2',
        ]), $response);
    }

    public function testDecodeServerResponse(): void
    {
        $response = $this->encoder->decode(
            (string) hex2bin('727370617574683d3239306664633430623436626164303735663861303863663734333631666363'),
            new SaslContext(),
        );

        self::assertEquals(new Message(['rspauth' => '290fdc40b46bad075f8a08cf74361fcc']), $response);
    }

    public function testEncodeServerChallenge(): void
    {
        $challenge = new Message([
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'realm' => 'huh-sys',
            'qop' => ['auth', 'auth-int', 'auth-conf'],
            'cipher' => ['rc4-40', 'rc4-56', 'rc4', 'des', '3des'],
            'maxbuf' => '65536',
            'charset' => 'utf-8',
            'algorithm' => 'md5-sess',
        ]);

        self::assertSame(
            (string) hex2bin('6e6f6e63653d226949414951483035755176705a6d6d3258522b696833644456337a7554696478744d4f33507346475253493d222c7265616c6d3d226875682d737973222c716f703d22617574682c617574682d696e742c617574682d636f6e66222c6369706865723d227263342d34302c7263342d35362c7263342c6465732c33646573222c6d61786275663d36353533362c636861727365743d7574662d382c616c676f726974686d3d6d64352d73657373'),
            $this->encoder->encode($challenge, (new SaslContext())->setIsServerMode(true)),
        );
    }

    public function testEncodeClientResponse(): void
    {
        $response = new Message([
            'username' => 'WillifoA',
            'realm' => 'huh-sys',
            'nonce' => 'iIAIQH05uQvpZmm2XR+ih3dDV3zuTidxtMO3PsFGRSI=',
            'cnonce' => 'jSo4loL8WWrHo50BImsqjSRBKMAoXDDXrjNGCfY2v+Q=',
            'nc' => 1,
            'qop' => 'auth-conf',
            'cipher' => 'rc4',
            'maxbuf' => '16777215',
            'digest-uri' => 'ldap/huh-sys',
            'response' => '16c0ee7bfa5fcc3b2d19b50f17ebb8f2',
        ]);

        self::assertSame(
            (string) hex2bin('757365726e616d653d2257696c6c69666f41222c7265616c6d3d226875682d737973222c6e6f6e63653d226949414951483035755176705a6d6d3258522b696833644456337a7554696478744d4f33507346475253493d222c636e6f6e63653d226a536f346c6f4c38575772486f353042496d73716a5352424b4d416f58444458726a4e4743665932762b513d222c6e633d30303030303030312c716f703d617574682d636f6e662c6369706865723d7263342c6d61786275663d31363737373231352c6469676573742d7572693d226c6461702f6875682d737973222c726573706f6e73653d3136633065653762666135666363336232643139623530663137656262386632'),
            $this->encoder->encode($response, new SaslContext()),
        );
    }

    public function testEncodeServerResponse(): void
    {
        $response = new Message(['rspauth' => '290fdc40b46bad075f8a08cf74361fcc']);

        self::assertSame(
            (string) hex2bin('727370617574683d3239306664633430623436626164303735663861303863663734333631666363'),
            $this->encoder->encode($response, (new SaslContext())->setIsServerMode(true)),
        );
    }

    public function testDecodingThrowsExceptionOnMalformedKeys(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('The digest is malformed. Expected a key, but none was found.'));

        $this->encoder->decode('f00=bar', new SaslContext());
    }

    public function testDecodingThrowsExceptionWhenKeyValuesDoNotHaveACommaAfterThem(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('Expected a comma following digest value for username.'));

        $this->encoder->decode('username="foo"foo=bar', new SaslContext());
    }

    public function testDecodingThrowsAnExceptionWhenAKeyIsNotRecognized(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('Digest option foo is not supported.'));

        $this->encoder->decode('foo="bar"', new SaslContext());
    }

    public function testDecodingThrowsAnExceptionWhenStaleIsNotTrue(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('Expected the directive value to be "true", but it is not.'));

        $this->encoder->decode('stale=false', new SaslContext());
    }

    public function testDecodingThrowsAnExceptionWhenAlgorithmIsNotMD5Sess(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('Expected the directive value to be "md5-sess", but it is not.'));

        $this->encoder->decode('algorithm=foo', new SaslContext());
    }

    public function testDecodingThrowsAnExceptionWhenCharsetIsNotUTF8(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('Expected the directive value to be "utf-8", but it is not.'));

        $this->encoder->decode('charset=en-us', new SaslContext());
    }

    public function testDecodingThatCharsetMayOnlyOccurOnce(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('The option "charset" may occur only once.'));

        $this->encoder->decode('charset=utf-8,charset=utf-8', new SaslContext());
    }

    public function testDecodingThatStaleMayOnlyOccurOnce(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('The option "stale" may occur only once.'));

        $this->encoder->decode('stale=true,stale=true', new SaslContext());
    }

    public function testDecodingThatAlgorithmMayOnlyOccurOnce(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('The option "algorithm" may occur only once.'));

        $this->encoder->decode('algorithm=md5-sess,algorithm=md5-sess', new SaslContext());
    }

    public function testDecodingThatNonceMayOnlyOccurOnce(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('The option "nonce" may occur only once.'));

        $this->encoder->decode('nonce="fooo",nonce="barr"', new SaslContext());
    }

    public function testDecodingThatCnonceMayOnlyOccurOnce(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('The option "cnonce" may occur only once.'));

        $this->encoder->decode('cnonce="fooo",cnonce="barr"', new SaslContext());
    }

    public function testDecodingThatNcMayOnlyOccurOnce(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('The option "nc" may occur only once.'));

        $this->encoder->decode('nc=00000001,nc=00000002', new SaslContext());
    }

    public function testDecodingThatQopMayOnlyOccurOnce(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('The option "qop" may occur only once.'));

        $this->encoder->decode('qop="auth-int",qop="auth-conf"', new SaslContext());
    }

    public function testDecodingThatDigestUriMayOnlyOccurOnce(): void
    {
        $this->expectExceptionObject(new SaslEncodingException('The option "digest-uri" may occur only once.'));

        $this->encoder->decode('digest-uri="foo/bar",digest-uri="bar/foo"', new SaslContext());
    }

    public function testDecodingQuotedValuesWithEscapedQuotes(): void
    {
        $message = $this->encoder->decode('username="foo\"bar"', new SaslContext());

        self::assertSame('foo"bar', $message->get('username'));
    }

    public function testDecodingCorrectlyUnescapesCharactersInQuotedStrings(): void
    {
        $message = $this->encoder->decode('username="\f\o\o\\\\b\a\r\""', new SaslContext());

        self::assertSame('foo\bar"', $message->get('username'));
    }

    public function testEncodingCorrectlyEscapesCharactersInQuotedStrings(): void
    {
        self::assertSame(
            'username="foo\\\bar\""',
            $this->encoder->encode(new Message(['username' => 'foo\bar"']), new SaslContext()),
        );
    }
}
