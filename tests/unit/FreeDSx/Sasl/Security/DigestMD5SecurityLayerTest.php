<?php
/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl\Security;

use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\Security\DigestMD5SecurityLayer;
use PHPUnit\Framework\TestCase;

class DigestMD5SecurityLayerTest extends TestCase
{
    /**
     * @var DigestMD5SecurityLayer
     */
    protected $security;

    /**
     * @var SaslContext
     */
    protected $clientContext;

    /**
     * @var SaslContext
     */
    protected $serverContext;

    public function setUp()
    {
        $this->security = new DigestMD5SecurityLayer();
        $this->clientContext = new SaslContext();
        $this->clientContext->setData([
            "username" => "WillifoA",
            "digest-uri" => "ldap/huh-sys",
            "qop" => "auth-conf",
            "seqnumrcv" => 0,
            "seqnumsnt" => 0,
        ]);
        $this->clientContext->setIsAuthenticated(true);
        $this->clientContext->setHasSecurityLayer(true);

        $this->serverContext = new SaslContext();
        $this->serverContext->setData([
            "username" => "WillifoA",
            "digest-uri" => "ldap/huh-sys",
            "qop" => "auth-conf",
            "seqnumrcv" => 0,
            "seqnumsnt" => 0,
        ]);
        $this->serverContext->setIsAuthenticated(true);
        $this->serverContext->setHasSecurityLayer(true);
        $this->serverContext->setIsServerMode(true);
    }

    public function testUnWrapWithPrivacyRC4SeqNumNonZero()
    {
        $this->markTestSkipped('Messages past the first sequence number do not decrypt. Unable to determine what is actually wrong here.');

        $this->clientContext->set('a1', hex2bin("5c002ca5ad1405892f3a5e4bc594b08a"));
        $this->clientContext->set('cipher', 'rc4');
        $this->clientContext->set('seqnumrcv', 1);
        $this->clientContext->set('seqnumsnt', 1);

        $this->serverContext->set('a1', hex2bin("5c002ca5ad1405892f3a5e4bc594b08a"));
        $this->serverContext->set('cipher', 'rc4');
        $this->serverContext->set('seqnumrcv', 1);
        $this->serverContext->set('seqnumsnt', 1);

        $resdoneMsg = hex2bin('300c02010365070a010004000400');
        #$resentryMsg = hex2bin('3070020103646b0446636e3d41646d696e2057696c6c69666f72642c6f753d41646d696e6973747261746976652c6f753d467265654453782d546573742c64633d6578616d706c652c64633d636f6d3021301f04046d61696c3117041557696c6c69666f41406e732d6d61696c382e636f6d');
        $resdoneEnc = hex2bin('20ebcfb4998c974483008a48f3003202ba151ab98074035e000100000001');
        #$resEntryEnc = hex2bin('d73c8d2c02c2f5f1fe37b4d7bd0c40ca8906b888ee8be3da1434558a42992e041dbd28ff6f53fab9136aece40ae15905144a76a55bf1b6560a9ffa558158cc05e5b97eb9206615dede875c73a8df036dcf7d200e1acf49125310818f8a5972be65f3367c26f9007441887346bd39ea9ba063ee81f599bc119cba6939000100000000');

        $this->assertEquals(
            $resdoneEnc,
            $this->security->wrap($resdoneMsg, $this->serverContext)
        );
    }

    public function testWrapWithPrivacyRC4()
    {
        $this->clientContext->set('a1', hex2bin("960bcfc7a190d6b1dcabcd5bc7f53fe0"));
        $this->clientContext->set('cipher', 'rc4');
        $message = hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        $this->assertEquals(
            hex2bin('6c9849465f4a88af35b82a6b8f35295e8c60e9d17245f3a8fbe5be1ca6599d7aef09b7f5caf7f43a7eea74b02c669c6a9bb346ba863ab843cf51eccd5b0b570f912e910dd234000100000000'),
            $this->security->wrap($message, $this->clientContext)
        );
    }

    public function testUnwrapWithPrivacyRC4()
    {
        $this->serverContext->set('a1', hex2bin("960bcfc7a190d6b1dcabcd5bc7f53fe0"));
        $this->serverContext->set('cipher', 'rc4');
        $message = hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        $this->assertEquals(
            $message,
            $this->security->unwrap(hex2bin('6c9849465f4a88af35b82a6b8f35295e8c60e9d17245f3a8fbe5be1ca6599d7aef09b7f5caf7f43a7eea74b02c669c6a9bb346ba863ab843cf51eccd5b0b570f912e910dd234000100000000'), $this->serverContext)
        );
    }

    public function testWrapWithRC440()
    {
        $this->clientContext->set('a1', hex2bin('407a52fb725042db234e11b34fb5fd55'));
        $this->clientContext->set('cipher', 'rc4-40');
        $message = hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        $this->assertEquals(
            hex2bin('056173eaae8b7ac19b1f0d73e8e340c37e83b6ab23377f143b1d2722cf11657b1de53c61ce7a2898786b01a30ca940521c6ade80f01f155e798babc7a1275614656d1b74dee7000100000000'),
            $this->security->wrap($message, $this->clientContext)
        );
    }

    public function testUnwrapWithRC440()
    {
        $this->serverContext->set('a1', hex2bin('407a52fb725042db234e11b34fb5fd55'));
        $this->serverContext->set('cipher', 'rc4-40');
        $encrypted = hex2bin('056173eaae8b7ac19b1f0d73e8e340c37e83b6ab23377f143b1d2722cf11657b1de53c61ce7a2898786b01a30ca940521c6ade80f01f155e798babc7a1275614656d1b74dee7000100000000');

        $this->assertEquals(
            hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000'),
            $this->security->unwrap($encrypted, $this->serverContext)
        );
    }

    public function testWrapWithRC456()
    {
        $this->markTestSkipped('Cipher unavailable.');

        $this->clientContext->set('a1', hex2bin('3b39571696572c05957522d94817ce46'));
        $this->clientContext->set('cipher', 'rc4-56');
        $message = hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        $this->assertEquals(
            hex2bin('96979065bdf4d9633698c2213aefd9e7ff99fb63d6bb10a65a67afc3cef4104f10a3e1855430c08c4539ce8e034717df84c537fb82f4e2bb8e6939806b18fcb7882feee2faeb000100000000'),
            $this->security->wrap($message, $this->clientContext)
        );
    }

    public function testUnwrapWithRC456()
    {
        $this->markTestSkipped('Cipher unavailable.');

        $this->serverContext->set('a1', hex2bin('3b39571696572c05957522d94817ce46'));
        $this->serverContext->set('cipher', 'rc4-56');
        $encrypted = hex2bin('96979065bdf4d9633698c2213aefd9e7ff99fb63d6bb10a65a67afc3cef4104f10a3e1855430c08c4539ce8e034717df84c537fb82f4e2bb8e6939806b18fcb7882feee2faeb000100000000');


        $this->assertEquals(
            hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000'),
            $this->security->unwrap($encrypted, $this->serverContext)
        );
    }

    public function testWrapWithPrivacyDes()
    {
        $this->markTestIncomplete('Still needs to be tested with DES data.');
    }

    public function testUnwrapWithPrivacyDes()
    {
        $this->markTestIncomplete('Still needs to be tested with DES data.');
    }

    public function testWrapWithPrivacy3Des()
    {
        $this->clientContext->set('a1', hex2bin('9969a25310dd52c864715057ca181374'));
        $this->clientContext->set('cipher', '3des');
        $message = hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        $this->assertEquals(
            hex2bin('73ebc692c839c8382c4bc669076fa893d1deaca630a1c74dcb0354159680372e555863e2e609a0ce72f06b7bb64fed4e3cf30057af5fd23ff6e0ffda06eb7fdb67edc8b331723f02000100000000'),
            $this->security->wrap($message, $this->clientContext)
        );
    }

    public function testUnwrapWithPrivacy3Des()
    {
        $this->serverContext->set('a1', hex2bin('9969a25310dd52c864715057ca181374'));
        $this->serverContext->set('cipher', '3des');
        $encrypted = hex2bin('73ebc692c839c8382c4bc669076fa893d1deaca630a1c74dcb0354159680372e555863e2e609a0ce72f06b7bb64fed4e3cf30057af5fd23ff6e0ffda06eb7fdb67edc8b331723f02000100000000');

        $this->assertEquals(
            hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000'),
            $this->security->unwrap($encrypted, $this->serverContext)
        );
    }

    public function testWrapWithOnlyIntegrity()
    {
        $this->clientContext->set('a1', hex2bin('7b712f824ba6ad44548ba16b2ec75988'));
        $this->clientContext->set('qop', 'auth-int');
        $message = hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000');

        $this->assertEquals(
            hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f41300086e03fcc17597a6dfb1c000100000000'),
            $this->security->wrap($message, $this->clientContext)
        );
    }

    public function testUnwrapWithOnlyIntegrity()
    {
        $this->serverContext->set('a1', hex2bin('7b712f824ba6ad44548ba16b2ec75988'));
        $this->serverContext->set('qop', 'auth-int');

        $this->assertEquals(
            hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f413000'),
            $this->security->unwrap(hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f41300086e03fcc17597a6dfb1c000100000000'), $this->serverContext)
        );
    }

    public function testThatItThrowsAnExceptionIfTheWrappedDataExceedsTheBufferSizeDuringUnwrap()
    {
        $context = new SaslContext(['maxbuf' => 2, 'qop' => 'auth-int']);
        $this->expectExceptionMessage('The wrapped buffer exceeds the maxbuf length of 2');
        $this->security->unwrap('foo', $context);
    }


    public function testThatItThrowsAnExceptionIfTheWrappedDataExceedsTheBufferSizeDuringWrap()
    {
        $this->serverContext->set('a1', hex2bin('7b712f824ba6ad44548ba16b2ec75988'));
        $this->serverContext->set('qop', 'auth-int');
        $this->serverContext->set('maxbuf', 2);

        $this->expectExceptionMessage('The wrapped buffer exceeds the maxbuf length of 2');
        $this->security->unwrap(hex2bin('303a0201036335041164633d6578616d706c652c64633d636f6d0a01020a0100020100020100010100a30f0403756964040857696c6c69666f41300086e03fcc17597a6dfb1c000100000000'), $this->serverContext);
    }
}
