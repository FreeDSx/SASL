<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Challenge\ScramChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use PHPUnit\Framework\TestCase;

/**
 * Test vectors from RFC 5802 Appendix B (SCRAM-SHA-1):
 *
 *   username:  user
 *   password:  pencil
 *   cnonce:    fyko+d2lbbFgONRv9qkxdawL
 *   snonce:    3rfcNHYJY1ZVvWVs7j
 *   salt:      QSXCR+Q6sek8bf92  (base64)
 *   iterations: 4096
 *
 *   C: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
 *   S: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096
 *   C: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
 *   S: v=rmF9pqV8S7suAoZWja4dJRkFsKQ=
 */
class ScramChallengeTest extends TestCase
{
    private const USERNAME   = 'user';
    private const PASSWORD   = 'pencil';
    private const CNONCE     = 'fyko+d2lbbFgONRv9qkxdawL';
    private const SNONCE     = '3rfcNHYJY1ZVvWVs7j';
    private const SALT_B64   = 'QSXCR+Q6sek8bf92';
    private const ITERATIONS = 4096;

    private const CLIENT_FIRST = 'n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL';
    private const SERVER_FIRST = 'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096';
    private const CLIENT_FINAL = 'c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=';
    private const SERVER_FINAL = 'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=';

    /**
     * @var ScramChallenge
     */
    private $challenge;

    public function setUp(): void
    {
        parent::setUp();

        $this->challenge = new ScramChallenge(false, 'sha1');
    }

    public function testClientFirstMessageMatchesRfcVector(): void
    {
        $context = $this->challenge->challenge(null, [
            'username' => self::USERNAME,
            'cnonce'   => self::CNONCE,
        ]);

        $this->assertSame(
            self::CLIENT_FIRST,
            $context->getResponse()
        );
        $this->assertFalse($context->isComplete());
    }

    public function testClientFinalMessageMatchesRfcVector(): void
    {
        $this->challenge->challenge(null, [
            'username' => self::USERNAME,
            'cnonce'   => self::CNONCE,
        ]);

        $context = $this->challenge->challenge(self::SERVER_FIRST, [
            'password' => self::PASSWORD,
        ]);

        $this->assertSame(
            self::CLIENT_FINAL,
            $context->getResponse()
        );
        $this->assertFalse($context->isComplete());
    }

    public function testClientCompletesAndAuthenticatesOnValidServerFinal(): void
    {
        $this->challenge->challenge(
            null,
            [
                'username' => self::USERNAME,
                'cnonce' => self::CNONCE
            ]
        );
        $this->challenge->challenge(
            self::SERVER_FIRST,
            ['password' => self::PASSWORD]
        );
        $context = $this->challenge->challenge(self::SERVER_FINAL);

        $this->assertNull($context->getResponse());
        $this->assertTrue($context->isComplete());
        $this->assertTrue($context->isAuthenticated());
    }

    public function testClientThrowsExceptionOnServerFinalWithError(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            [
                'username' => self::USERNAME,
                'cnonce' => self::CNONCE
            ]
        );
        $this->challenge->challenge(
            self::SERVER_FIRST,
            ['password' => self::PASSWORD]
        );
        $this->challenge->challenge('e=unknown-user');
    }

    public function testClientThrowsExceptionOnInvalidServerSignature(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            ['username' => self::USERNAME, 'cnonce' => self::CNONCE]
        );
        $this->challenge->challenge(
            self::SERVER_FIRST,
            ['password' => self::PASSWORD]
        );
        $this->challenge->challenge('v=aW52YWxpZHNpZ25hdHVyZQ==');
    }

    public function testClientThrowsExceptionWhenNonceDoesNotBeginWithClientNonce(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            [
                'username' => self::USERNAME,
                'cnonce' => self::CNONCE
            ]
        );
        // Server-first with a nonce that doesn't start with the client nonce
        $this->challenge->challenge(
            'r=wrongnonce,s=' . self::SALT_B64 . ',i=' . self::ITERATIONS,
            ['password' => self::PASSWORD]
        );
    }

    public function testClientThrowsExceptionWhenUsernameIsMissing(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge();
    }

    public function testClientThrowsExceptionWhenPasswordIsMissing(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            [
                'username' => self::USERNAME,
                'cnonce' => self::CNONCE
            ]
        );
        $this->challenge->challenge(self::SERVER_FIRST);
    }

    public function testClientEncodesSpecialCharactersInUsername(): void
    {
        $context = $this->challenge->challenge(null, [
            'username' => 'user=name,test',
            'cnonce'   => self::CNONCE,
        ]);

        $this->assertStringContainsString(
            'n=user=3Dname=2Ctest',
            (string) $context->getResponse()
        );
    }

    public function testChannelBindingClientFirstUsesCorrectGs2Header(): void
    {
        $plusChallenge = new ScramChallenge(false, 'sha256', true);
        $context = $plusChallenge->challenge(null, [
            'username'   => self::USERNAME,
            'cnonce'     => self::CNONCE,
            'cbind_type' => 'tls-unique',
        ]);

        $this->assertStringStartsWith(
            'p=tls-unique,,',
            (string) $context->getResponse()
        );
    }

    public function testServerReturnsNullResponseForInitialCall(): void
    {
        $server = new ScramChallenge(
            true,
            'sha1',
            false
        );
        $context = $server->challenge();

        $this->assertNull($context->getResponse());
        $this->assertFalse($context->isComplete());
    }

    public function testServerFirstMessageContainsClientNoncePrefix(): void
    {
        $server = new ScramChallenge(
            true,
            'sha1',
            false
        );
        $context = $server->challenge(self::CLIENT_FIRST, [
            'nonce'      => self::SNONCE,
            'salt'       => base64_decode(self::SALT_B64),
            'iterations' => self::ITERATIONS,
        ]);

        $this->assertSame(
            self::SERVER_FIRST,
            $context->getResponse()
        );
        $this->assertFalse($context->isComplete());
    }

    public function testServerFinalMessageOnValidProof(): void
    {
        $server = new ScramChallenge(
            true,
            'sha1',
            false
        );
        $server->challenge(self::CLIENT_FIRST, [
            'nonce'      => self::SNONCE,
            'salt'       => base64_decode(self::SALT_B64),
            'iterations' => self::ITERATIONS,
        ]);
        $context = $server->challenge(
            self::CLIENT_FINAL,
            ['password' => self::PASSWORD]
        );

        $this->assertSame(
            self::SERVER_FINAL,
            $context->getResponse()
        );
        $this->assertTrue($context->isComplete());
        $this->assertTrue($context->isAuthenticated());
    }

    public function testServerFinalMessageOnInvalidProof(): void
    {
        $server = new ScramChallenge(true, 'sha1', false);
        $server->challenge(self::CLIENT_FIRST, [
            'nonce'      => self::SNONCE,
            'salt'       => base64_decode(self::SALT_B64),
            'iterations' => self::ITERATIONS,
        ]);
        // Send a valid-looking client-final but with the wrong password on the server
        $context = $server->challenge(self::CLIENT_FINAL, ['password' => 'wrongpassword']);

        $this->assertStringStartsWith(
            'e=',
            (string) $context->getResponse()
        );
        $this->assertTrue($context->isComplete());
        $this->assertFalse($context->isAuthenticated());
    }

    public function testServerFinalMessageWhenPasswordIsMissing(): void
    {
        $server = new ScramChallenge(
            true,
            'sha1',
            false
        );
        $server->challenge(self::CLIENT_FIRST, [
            'nonce'      => self::SNONCE,
            'salt'       => base64_decode(self::SALT_B64),
            'iterations' => self::ITERATIONS,
        ]);
        $context = $server->challenge(self::CLIENT_FINAL, []);

        $this->assertSame(
            'e=invalid-proof',
            $context->getResponse()
        );
        $this->assertTrue($context->isComplete());
        $this->assertFalse($context->isAuthenticated());
    }

    public function testClientThrowsExceptionWhenServerIterationCountIsBelowMinimum(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            ['username' => self::USERNAME, 'cnonce' => self::CNONCE]
        );
        // i=1 is below the SHA-1 minimum of 4096
        $this->challenge->challenge(
            'r=' . self::CNONCE . self::SNONCE . ',s=' . self::SALT_B64 . ',i=1',
            ['password' => self::PASSWORD]
        );
    }

    public function testServerThrowsExceptionWhenSuppliedIterationCountIsZero(): void
    {
        $this->expectException(SaslException::class);

        $server = new ScramChallenge(true, 'sha1', false);
        $server->challenge(self::CLIENT_FIRST, [
            'nonce'      => self::SNONCE,
            'salt'       => base64_decode(self::SALT_B64),
            'iterations' => 0,
        ]);
    }

    public function testClientThrowsExceptionOnInvalidBase64Salt(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            ['username' => self::USERNAME, 'cnonce' => self::CNONCE]
        );
        // s= value is not valid base64
        $this->challenge->challenge(
            'r=' . self::CNONCE . self::SNONCE . ',s=not!!valid!!base64,i=' . self::ITERATIONS,
            ['password' => self::PASSWORD]
        );
    }

    public function testServerReturnsInvalidProofOnMalformedBase64Proof(): void
    {
        $server = new ScramChallenge(true, 'sha1', false);
        $server->challenge(self::CLIENT_FIRST, [
            'nonce'      => self::SNONCE,
            'salt'       => base64_decode(self::SALT_B64),
            'iterations' => self::ITERATIONS,
        ]);
        // Replace the valid proof with invalid base64
        $tampered = preg_replace('/,p=[^,]+$/', ',p=not!!valid', self::CLIENT_FINAL);
        $context = $server->challenge($tampered, ['password' => self::PASSWORD]);

        $this->assertSame('e=invalid-proof', $context->getResponse());
        $this->assertFalse($context->isAuthenticated());
    }

    public function testClientThrowsExceptionWhenClientFinalCalledWithoutClientFirst(): void
    {
        $this->expectException(SaslException::class);

        // Skip client-first and call directly with a server-first message
        $this->challenge->challenge(
            self::SERVER_FIRST,
            ['password' => self::PASSWORD]
        );
    }

    public function testClientThrowsExceptionOnInvalidChannelBindingType(): void
    {
        $this->expectException(SaslException::class);

        $plusChallenge = new ScramChallenge(false, 'sha256', true);
        $plusChallenge->challenge(null, [
            'username'   => self::USERNAME,
            'cnonce'     => self::CNONCE,
            'cbind_type' => 'invalid,,type',
        ]);
    }

    public function testThrowsExceptionOnUnsupportedHashAlgorithm(): void
    {
        $this->expectException(SaslException::class);

        new ScramChallenge(false, 'md5');
    }

    public function testClientThrowsExceptionWhenServerIterationCountExceedsMaximum(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            ['username' => self::USERNAME, 'cnonce' => self::CNONCE]
        );
        $this->challenge->challenge(
            'r=' . self::CNONCE . self::SNONCE . ',s=' . self::SALT_B64 . ',i=1000001',
            ['password' => self::PASSWORD]
        );
    }

    public function testServerThrowsExceptionWhenSuppliedIterationCountExceedsMaximum(): void
    {
        $this->expectException(SaslException::class);

        $server = new ScramChallenge(true, 'sha1', false);
        $server->challenge(self::CLIENT_FIRST, [
            'nonce'      => self::SNONCE,
            'salt'       => base64_decode(self::SALT_B64),
            'iterations' => 1000001,
        ]);
    }

    public function testClientThrowsExceptionOnEmptyCnonce(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(null, [
            'username' => self::USERNAME,
            'cnonce'   => '',
        ]);
    }

    public function testFullClientServerRoundTrip(): void
    {
        $client = new ScramChallenge(
            false,
            'sha256'
        );
        $server = new ScramChallenge(
            true,
            'sha256',
            false
        );

        // Round 1: client-first -> server
        $clientFirst = $client->challenge(
            null,
            ['username' => self::USERNAME]
        )->getResponse();
        $this->assertNotNull($clientFirst);

        // Round 2: server processes client-first, sends server-first
        $serverFirst = $server->challenge($clientFirst)->getResponse();
        $this->assertNotNull($serverFirst);

        // Round 3: client processes server-first, sends client-final
        $clientFinal = $client->challenge(
            $serverFirst,
            ['password' => self::PASSWORD]
        )->getResponse();
        $this->assertNotNull($clientFinal);

        // Round 4: server processes client-final, sends server-final
        $serverContext = $server->challenge(
            $clientFinal,
            ['password' => self::PASSWORD]
        );
        $serverFinal = $serverContext->getResponse();
        $this->assertStringStartsWith(
            'v=',
            (string) $serverFinal
        );
        $this->assertTrue($serverContext->isAuthenticated());

        // Round 5: client verifies server-final
        $clientContext = $client->challenge($serverFinal);
        $this->assertTrue($clientContext->isComplete());
        $this->assertTrue($clientContext->isAuthenticated());
    }
}
