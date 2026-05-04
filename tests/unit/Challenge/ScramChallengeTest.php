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

namespace Tests\Unit\FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Challenge\ScramChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\HashAlgorithm;
use FreeDSx\Sasl\Options\ScramOptions;
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
 */
final class ScramChallengeTest extends TestCase
{
    private const USERNAME = 'user';

    private const PASSWORD = 'pencil';

    private const CNONCE = 'fyko+d2lbbFgONRv9qkxdawL';

    private const SNONCE = '3rfcNHYJY1ZVvWVs7j';

    private const SALT_B64 = 'QSXCR+Q6sek8bf92';

    private const ITERATIONS = 4096;

    private const CLIENT_FIRST = 'n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL';

    private const SERVER_FIRST = 'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096';

    private const CLIENT_FINAL = 'c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=';

    private const SERVER_FINAL = 'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=';

    private ScramChallenge $challenge;

    protected function setUp(): void
    {
        $this->challenge = new ScramChallenge(false, HashAlgorithm::SHA1);
    }

    public function testClientFirstMessageMatchesRfcVector(): void
    {
        $context = $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );

        self::assertSame(self::CLIENT_FIRST, $context->getResponse());
        self::assertFalse($context->isComplete());
    }

    public function testClientFinalMessageMatchesRfcVector(): void
    {
        $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );

        $context = $this->challenge->challenge(
            self::SERVER_FIRST,
            (new ScramOptions())->setPassword(self::PASSWORD),
        );

        self::assertSame(self::CLIENT_FINAL, $context->getResponse());
        self::assertFalse($context->isComplete());
    }

    public function testClientCompletesAndAuthenticatesOnValidServerFinal(): void
    {
        $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );
        $this->challenge->challenge(
            self::SERVER_FIRST,
            (new ScramOptions())->setPassword(self::PASSWORD),
        );
        $context = $this->challenge->challenge(self::SERVER_FINAL);

        self::assertNull($context->getResponse());
        self::assertTrue($context->isComplete());
        self::assertTrue($context->isAuthenticated());
    }

    public function testClientThrowsExceptionOnServerFinalWithError(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );
        $this->challenge->challenge(
            self::SERVER_FIRST,
            (new ScramOptions())->setPassword(self::PASSWORD),
        );
        $this->challenge->challenge('e=unknown-user');
    }

    public function testClientThrowsExceptionOnInvalidServerSignature(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );
        $this->challenge->challenge(
            self::SERVER_FIRST,
            (new ScramOptions())->setPassword(self::PASSWORD),
        );
        $this->challenge->challenge('v=aW52YWxpZHNpZ25hdHVyZQ==');
    }

    public function testClientThrowsExceptionWhenNonceDoesNotBeginWithClientNonce(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );
        $this->challenge->challenge(
            'r=wrongnonce,s=' . self::SALT_B64 . ',i=' . self::ITERATIONS,
            (new ScramOptions())->setPassword(self::PASSWORD),
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
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );
        $this->challenge->challenge(self::SERVER_FIRST);
    }

    public function testClientEncodesSpecialCharactersInUsername(): void
    {
        $context = $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername('user=name,test')->setCnonce(self::CNONCE),
        );

        self::assertStringContainsString('n=user=3Dname=2Ctest', (string) $context->getResponse());
    }

    public function testChannelBindingClientFirstUsesCorrectGs2Header(): void
    {
        $plusChallenge = new ScramChallenge(false, HashAlgorithm::SHA256, true);
        $context = $plusChallenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE)->setCbindType('tls-unique'),
        );

        self::assertStringStartsWith('p=tls-unique,,', (string) $context->getResponse());
    }

    public function testServerReturnsNullResponseForInitialCall(): void
    {
        $server = new ScramChallenge(true, HashAlgorithm::SHA1);
        $context = $server->challenge();

        self::assertNull($context->getResponse());
        self::assertFalse($context->isComplete());
    }

    public function testServerFirstMessageContainsClientNoncePrefix(): void
    {
        $server = new ScramChallenge(true, HashAlgorithm::SHA1);
        $context = $server->challenge(
            self::CLIENT_FIRST,
            (new ScramOptions())
                ->setNonce(self::SNONCE)
                ->setSalt((string) base64_decode(self::SALT_B64))
                ->setIterations(self::ITERATIONS),
        );

        self::assertSame(self::SERVER_FIRST, $context->getResponse());
        self::assertFalse($context->isComplete());
    }

    public function testServerFinalMessageOnValidProof(): void
    {
        $server = new ScramChallenge(true, HashAlgorithm::SHA1);
        $server->challenge(
            self::CLIENT_FIRST,
            (new ScramOptions())
                ->setNonce(self::SNONCE)
                ->setSalt((string) base64_decode(self::SALT_B64))
                ->setIterations(self::ITERATIONS),
        );
        $context = $server->challenge(
            self::CLIENT_FINAL,
            (new ScramOptions())->setPassword(self::PASSWORD),
        );

        self::assertSame(self::SERVER_FINAL, $context->getResponse());
        self::assertTrue($context->isComplete());
        self::assertTrue($context->isAuthenticated());
    }

    public function testServerFinalMessageOnInvalidProof(): void
    {
        $server = new ScramChallenge(true, HashAlgorithm::SHA1);
        $server->challenge(
            self::CLIENT_FIRST,
            (new ScramOptions())
                ->setNonce(self::SNONCE)
                ->setSalt((string) base64_decode(self::SALT_B64))
                ->setIterations(self::ITERATIONS),
        );
        $context = $server->challenge(
            self::CLIENT_FINAL,
            (new ScramOptions())->setPassword('wrongpassword'),
        );

        self::assertStringStartsWith('e=', (string) $context->getResponse());
        self::assertTrue($context->isComplete());
        self::assertFalse($context->isAuthenticated());
    }

    public function testServerFinalMessageWhenPasswordIsMissing(): void
    {
        $server = new ScramChallenge(true, HashAlgorithm::SHA1);
        $server->challenge(
            self::CLIENT_FIRST,
            (new ScramOptions())
                ->setNonce(self::SNONCE)
                ->setSalt((string) base64_decode(self::SALT_B64))
                ->setIterations(self::ITERATIONS),
        );
        $context = $server->challenge(self::CLIENT_FINAL);

        self::assertSame('e=invalid-proof', $context->getResponse());
        self::assertTrue($context->isComplete());
        self::assertFalse($context->isAuthenticated());
    }

    public function testClientThrowsExceptionWhenServerIterationCountIsBelowMinimum(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );
        $this->challenge->challenge(
            'r=' . self::CNONCE . self::SNONCE . ',s=' . self::SALT_B64 . ',i=1',
            (new ScramOptions())->setPassword(self::PASSWORD),
        );
    }

    public function testServerThrowsExceptionWhenSuppliedIterationCountIsZero(): void
    {
        $this->expectException(SaslException::class);

        $server = new ScramChallenge(true, HashAlgorithm::SHA1);
        $server->challenge(
            self::CLIENT_FIRST,
            (new ScramOptions())
                ->setNonce(self::SNONCE)
                ->setSalt((string) base64_decode(self::SALT_B64))
                ->setIterations(0),
        );
    }

    public function testClientThrowsExceptionOnInvalidBase64Salt(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );
        $this->challenge->challenge(
            'r=' . self::CNONCE . self::SNONCE . ',s=not!!valid!!base64,i=' . self::ITERATIONS,
            (new ScramOptions())->setPassword(self::PASSWORD),
        );
    }

    public function testServerReturnsInvalidProofOnMalformedBase64Proof(): void
    {
        $server = new ScramChallenge(true, HashAlgorithm::SHA1);
        $server->challenge(
            self::CLIENT_FIRST,
            (new ScramOptions())
                ->setNonce(self::SNONCE)
                ->setSalt((string) base64_decode(self::SALT_B64))
                ->setIterations(self::ITERATIONS),
        );
        $tampered = (string) preg_replace('/,p=[^,]+$/', ',p=not!!valid', self::CLIENT_FINAL);
        $context = $server->challenge($tampered, (new ScramOptions())->setPassword(self::PASSWORD));

        self::assertSame('e=invalid-proof', $context->getResponse());
        self::assertFalse($context->isAuthenticated());
    }

    public function testClientThrowsExceptionWhenClientFinalCalledWithoutClientFirst(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            self::SERVER_FIRST,
            (new ScramOptions())->setPassword(self::PASSWORD),
        );
    }

    public function testClientThrowsExceptionOnInvalidChannelBindingType(): void
    {
        $this->expectException(SaslException::class);

        $plusChallenge = new ScramChallenge(false, HashAlgorithm::SHA256, true);
        $plusChallenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE)->setCbindType('invalid,,type'),
        );
    }

    public function testClientThrowsExceptionWhenServerIterationCountExceedsMaximum(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(self::CNONCE),
        );
        $this->challenge->challenge(
            'r=' . self::CNONCE . self::SNONCE . ',s=' . self::SALT_B64 . ',i=1000001',
            (new ScramOptions())->setPassword(self::PASSWORD),
        );
    }

    public function testServerThrowsExceptionWhenSuppliedIterationCountExceedsMaximum(): void
    {
        $this->expectException(SaslException::class);

        $server = new ScramChallenge(true, HashAlgorithm::SHA1);
        $server->challenge(
            self::CLIENT_FIRST,
            (new ScramOptions())
                ->setNonce(self::SNONCE)
                ->setSalt((string) base64_decode(self::SALT_B64))
                ->setIterations(1000001),
        );
    }

    public function testClientThrowsExceptionOnEmptyCnonce(): void
    {
        $this->expectException(SaslException::class);

        $this->challenge->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME)->setCnonce(''),
        );
    }

    public function testFullClientServerRoundTrip(): void
    {
        $client = new ScramChallenge(false, HashAlgorithm::SHA256);
        $server = new ScramChallenge(true, HashAlgorithm::SHA256);

        $clientFirst = $client->challenge(
            null,
            (new ScramOptions())->setUsername(self::USERNAME),
        )->getResponse();
        self::assertNotNull($clientFirst);

        $serverFirst = $server->challenge($clientFirst)->getResponse();
        self::assertNotNull($serverFirst);

        $clientFinal = $client->challenge(
            $serverFirst,
            (new ScramOptions())->setPassword(self::PASSWORD),
        )->getResponse();
        self::assertNotNull($clientFinal);

        $serverContext = $server->challenge(
            $clientFinal,
            (new ScramOptions())->setPassword(self::PASSWORD),
        );
        $serverFinal = $serverContext->getResponse();
        self::assertStringStartsWith('v=', (string) $serverFinal);
        self::assertTrue($serverContext->isAuthenticated());

        $clientContext = $client->challenge($serverFinal);
        self::assertTrue($clientContext->isComplete());
        self::assertTrue($clientContext->isAuthenticated());
    }
}
