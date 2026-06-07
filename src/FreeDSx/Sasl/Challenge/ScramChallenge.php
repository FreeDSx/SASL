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

namespace FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Encoder\ScramEncoder;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Factory\NonceTrait;
use FreeDSx\Sasl\Mechanism\HashAlgorithm;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\Options\ScramOptions;
use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\SaslPrep;

/**
 * The SCRAM challenge / response class (RFC 5802).
 *
 * Handles all SCRAM hash variants and both standard and channel-binding (-PLUS) variants.
 *
 * Client flow (client-first):
 *   1. challenge(null, options)          -> client-first-message
 *   2. challenge(server-first, options)  -> client-final-message (with proof)
 *   3. challenge(server-final, options)  -> null (verifies server signature, sets isAuthenticated)
 *
 * Server flow:
 *   1. challenge(null, options)          -> null (SCRAM is client-initiated)
 *   2. challenge(client-first, options)  -> server-first-message
 *   3. challenge(client-final, options)  -> server-final-message (v= or e=)
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ScramChallenge implements ChallengeInterface
{
    use NonceTrait;
    use ResolvesOptionsTrait;

    /**
     * Default nonce size in bytes. Produces ~32 base64 characters; well above the RFC 5802 minimum.
     */
    private const NONCE_SIZE = 24;

    /**
     * Minimum PBKDF2 iteration count the client will accept from a server, keyed by HashAlgorithm value.
     * Values follow RFC 5802 (SHA-1: 4096) and RFC 7677 (SHA-256: 4096).
     */
    private const MIN_ITERATIONS = [
        'sha1' => 4096,
        'sha224' => 4096,
        'sha256' => 4096,
        'sha384' => 4096,
        'sha512' => 4096,
        'sha3-512' => 4096,
    ];

    /**
     * Maximum PBKDF2 iteration count accepted from a server (or configured for a server). Values
     * above 1,000,000 are unlikely to reflect a legitimate security policy and risk client-side DoS.
     */
    private const MAX_ITERATIONS = 1000000;

    /**
     * Default PBKDF2 iteration count used when the server generates a challenge, keyed by
     * HashAlgorithm value. Based on RFC 8265 guidance (≥15,000 for SHA-256), scaled conservatively
     * for stronger hash variants.
     */
    private const DEFAULT_ITERATIONS = [
        'sha1' => 10000,
        'sha224' => 15000,
        'sha256' => 15000,
        'sha384' => 10000,
        'sha512' => 10000,
        'sha3-512' => 10000,
    ];

    private const HMAC_CLIENT_KEY = 'Client Key';

    private const HMAC_SERVER_KEY = 'Server Key';

    /**
     * Context keys used to thread state between challenge invocations.
     */
    private const CTX_GS2_HEADER = 'scram-gs2-header';

    private const CTX_CNONCE = 'scram-cnonce';

    private const CTX_CLIENT_FIRST_BARE = 'scram-client-first-bare';

    private const CTX_SERVER_SIGNATURE = 'scram-server-signature';

    private const CTX_NONCE = 'scram-nonce';

    private const CTX_SALT = 'scram-salt';

    private const CTX_ITERATIONS = 'scram-iterations';

    private const CTX_SERVER_FIRST = 'scram-server-first';

    private const INVALID_PROOF = 'e=invalid-proof';

    private readonly SaslContext $context;

    private readonly ScramEncoder $encoder;

    public function __construct(
        bool $isServerMode = false,
        private readonly HashAlgorithm $hashAlgorithm = HashAlgorithm::SHA256,
        private readonly bool $isChannelBinding = false,
    ) {
        $this->encoder = new ScramEncoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    public function challenge(
        ?string $received = null,
        ?ChallengeOptionsInterface $options = null,
    ): SaslContext {
        $resolved = $this->resolveOptions(
            $options ?? new ScramOptions(),
            ScramOptions::class,
        );

        # Keep the raw received string for auth-message construction before decoding.
        $rawReceived = $received;
        $message = $received !== null ? $this->encoder->decode($received, $this->context) : null;

        $response = $this->context->isServerMode()
            ? $this->generateServerResponse($message, $rawReceived, $resolved)
            : $this->generateClientResponse($message, $rawReceived, $resolved);

        $this->context->setResponse($response);

        return $this->context;
    }

    /**
     * @throws SaslException
     */
    private function generateClientResponse(
        ?Message $received,
        ?string $rawReceived,
        ScramOptions $options,
    ): ?string {
        # Step 1: No message yet — generate client-first-message.
        if ($received === null) {
            return $this->generateClientFirst($options);
        }

        # Step 2: Server-first-message received (contains 's' and 'i') — generate client-final-message.
        if ($received->has('s') && $received->has('i')) {
            return $this->generateClientFinal($received, (string) $rawReceived, $options);
        }

        # Step 3: Server-final-message received (contains 'v' or 'e') — verify and complete.
        if ($received->has('v') || $received->has('e')) {
            $this->verifyServerFinal($received);

            return null;
        }

        throw new SaslException('Unexpected SCRAM message received on the client.');
    }

    /**
     * @throws SaslException
     */
    private function generateServerResponse(
        ?Message $received,
        ?string $rawReceived,
        ScramOptions $options,
    ): ?string {
        # SCRAM is client-initiated — the server has no opening message.
        if ($received === null) {
            return null;
        }

        # Step 1: Client-first-message received (contains 'n' and 'r', no proof yet).
        if ($received->has('n') && $received->has('r') && !$received->has('p')) {
            return $this->generateServerFirst($received, (string) $rawReceived, $options);
        }

        # Step 2: Client-final-message received (contains channel binding 'c' and proof 'p').
        if ($received->has('c') && $received->has('p')) {
            return $this->generateServerFinal($received, $options);
        }

        throw new SaslException('Unexpected SCRAM message received on the server.');
    }

    /**
     * @throws SaslException
     */
    private function generateClientFirst(ScramOptions $options): string
    {
        $username = $options->getUsername();
        if ($username === null) {
            throw new SaslException('A username is required to initiate SCRAM authentication.');
        }

        $cnonce = $options->getCnonce() ?? $this->generateNonce(self::NONCE_SIZE);
        if ($cnonce === '') {
            throw new SaslException('The client nonce must not be empty.');
        }

        if ($this->isChannelBinding) {
            $cbindType = $options->getCbindType() ?? 'tls-unique';
            $this->validateCbindType($cbindType);
            $gs2Header = 'p=' . $cbindType . ',,';
        } else {
            $gs2Header = 'n,,';
        }

        # RFC 5802 §2: apply SASLprep before encoding the username.
        $username = SaslPrep::prepare($username);

        # RFC 5802 section 5.1: '=' and ',' in the username must be encoded.
        $username = str_replace(['=', ','], ['=3D', '=2C'], $username);

        $clientFirstBare = 'n=' . $username . ',r=' . $cnonce;

        $this->context->set(self::CTX_GS2_HEADER, $gs2Header);
        $this->context->set(self::CTX_CNONCE, $cnonce);
        $this->context->set(self::CTX_CLIENT_FIRST_BARE, $clientFirstBare);

        return $gs2Header . $clientFirstBare;
    }

    /**
     * @throws SaslException
     */
    private function generateClientFinal(
        Message $serverFirst,
        string $rawServerFirst,
        ScramOptions $options,
    ): string {
        $password = $options->getPassword();
        if ($password === null) {
            throw new SaslException('A password is required to complete SCRAM authentication.');
        }

        # Guard against out-of-order calls: client-first must have run first to populate the cnonce.
        $cnonce = $this->context->getStringOrFail(
            self::CTX_CNONCE,
            'client-final called before client-first: no client nonce found in context.',
        );

        # The full nonce must begin with the client nonce we sent — verify before processing anything else.
        [$fullNonce, $salt, $iterations] = $this->parseServerFirst($serverFirst, $cnonce);

        # Channel binding value: base64(gs2-header + cbind-data).
        $gs2Header = $this->context->getString(self::CTX_GS2_HEADER);
        $cbindData = $options->getCbindData() ?? '';
        $channelBinding = base64_encode($gs2Header . $cbindData);

        $clientFinalWithoutProof = 'c=' . $channelBinding . ',r=' . $fullNonce;

        # RFC 5802 §3: AuthMessage = client-first-bare "," server-first "," client-final-without-proof
        $authMessage = $this->context->getString(self::CTX_CLIENT_FIRST_BARE)
            . ',' . $rawServerFirst
            . ',' . $clientFinalWithoutProof;

        $saltedPassword = $this->deriveSaltedPassword($password, $salt, $iterations);
        $clientProof = $this->makeClientProof($saltedPassword, $authMessage);

        # Pre-compute the expected server signature so we can verify it in step 3.
        $serverKey = $this->hmac($saltedPassword, self::HMAC_SERVER_KEY);
        $serverSignature = $this->hmac($serverKey, $authMessage);
        $this->context->set(
            self::CTX_SERVER_SIGNATURE,
            base64_encode($serverSignature),
        );

        return $clientFinalWithoutProof . ',p=' . base64_encode($clientProof);
    }

    /**
     * @throws SaslException
     */
    private function verifyServerFinal(Message $serverFinal): void
    {
        $this->context->setIsComplete(true);

        if ($serverFinal->has('e')) {
            throw new SaslException(sprintf(
                'SCRAM authentication failed with server error: %s',
                $serverFinal->getString('e'),
            ));
        }

        $expectedSig = $this->context->getString(self::CTX_SERVER_SIGNATURE);
        $receivedSig = $serverFinal->getString('v');

        if (!hash_equals($expectedSig, $receivedSig)) {
            throw new SaslException('The server signature does not match the expected value.');
        }

        $this->context->setIsAuthenticated(true);
    }

    /**
     * @throws SaslException
     */
    private function generateServerFirst(
        Message $clientFirst,
        string $rawClientFirst,
        ScramOptions $options,
    ): string {
        $cnonce = $clientFirst->getString('r');
        $snonce = $options->getNonce() ?? $this->generateNonce(self::NONCE_SIZE);
        $fullNonce = $cnonce . $snonce;

        $salt = $options->getSalt() ?? random_bytes(16);
        $iterations = $options->getIterations() ?? self::DEFAULT_ITERATIONS[$this->hashAlgorithm->value];
        if ($iterations < 1) {
            throw new SaslException('The iteration count must be greater than zero.');
        }
        if ($iterations > self::MAX_ITERATIONS) {
            throw new SaslException(sprintf(
                'The iteration count of %d exceeds the maximum allowed of %d.',
                $iterations,
                self::MAX_ITERATIONS,
            ));
        }

        $clientFirstBare = $this->extractClientFirstBare($rawClientFirst);
        $serverFirst = 'r=' . $fullNonce . ',s=' . base64_encode($salt) . ',i=' . $iterations;

        $this->context->set(self::CTX_CLIENT_FIRST_BARE, $clientFirstBare);
        $this->context->set(self::CTX_NONCE, $fullNonce);
        $this->context->set(self::CTX_SALT, $salt);
        $this->context->set(self::CTX_ITERATIONS, $iterations);
        $this->context->set(self::CTX_SERVER_FIRST, $serverFirst);

        return $serverFirst;
    }

    /**
     * Returns 'v=<server-signature>' on success, or 'e=<error>' on failure.
     *
     * @throws SaslException
     */
    private function generateServerFinal(
        Message $clientFinal,
        ScramOptions $options,
    ): string {
        $this->context->setIsComplete(true);

        $password = $options->getPassword();
        if ($password === null) {
            return self::INVALID_PROOF;
        }

        $fullNonce = $this->context->getString(self::CTX_NONCE);
        $clientNonce = $clientFinal->getString('r');
        if ($clientNonce !== $fullNonce) {
            return self::INVALID_PROOF;
        }

        $salt = $this->context->getString(self::CTX_SALT);
        $iterations = $this->context->getInt(self::CTX_ITERATIONS) ?? 1;

        # RFC 5802: client-final-without-proof = c=...,r=...[,extensions] — fixed order, safely rebuildable.
        $clientFinalWithoutProof = 'c=' . $clientFinal->getString('c') . ',r=' . $clientNonce;
        $authMessage = $this->context->getString(self::CTX_CLIENT_FIRST_BARE)
            . ',' . $this->context->getString(self::CTX_SERVER_FIRST)
            . ',' . $clientFinalWithoutProof;

        try {
            $saltedPassword = $this->deriveSaltedPassword($password, $salt, $iterations);
        } catch (SaslException) {
            return self::INVALID_PROOF;
        }

        if (!$this->isValidClientProof($clientFinal, $saltedPassword, $authMessage)) {
            return self::INVALID_PROOF;
        }

        $serverKey = $this->hmac($saltedPassword, self::HMAC_SERVER_KEY);
        $serverSignature = $this->hmac($serverKey, $authMessage);

        $this->context->setIsAuthenticated(true);

        return 'v=' . base64_encode($serverSignature);
    }

    /**
     * Strips the GS2 header from the client-first-message, returning only the bare portion.
     *
     * GS2 header formats end with ',,': 'n,,', 'y,,', or 'p=type,,'.
     *
     * @throws SaslException
     */
    private function extractClientFirstBare(string $clientFirst): string
    {
        $pos = strpos(
            $clientFirst,
            ',,',
        );
        if ($pos === false) {
            throw new SaslException('Unable to parse GS2 header from client-first-message.');
        }

        return substr(
            $clientFirst,
            $pos + 2,
        );
    }

    /**
     * Validates and parses the server-first-message fields needed by the client.
     *
     * @return array{0: string, 1: string, 2: int} full nonce, salt, iterations
     *
     * @throws SaslException
     */
    private function parseServerFirst(
        Message $serverFirst,
        string $cnonce,
    ): array {
        $fullNonce = $serverFirst->getString('r');
        if (strncmp($fullNonce, $cnonce, strlen($cnonce)) !== 0) {
            throw new SaslException('The server nonce does not begin with the client nonce.');
        }

        $salt = base64_decode(
            $serverFirst->getString('s'),
            true,
        );
        if ($salt === false) {
            throw new SaslException('The server-provided salt is not valid base64.');
        }

        $iterations = $serverFirst->getIntOrParse('i') ?? 0;
        $minIterations = self::MIN_ITERATIONS[$this->hashAlgorithm->value];
        if ($iterations < $minIterations) {
            throw new SaslException(sprintf(
                'The server iteration count of %d is below the minimum of %d for %s.',
                $iterations,
                $minIterations,
                $this->hashAlgorithm->value,
            ));
        }
        if ($iterations > self::MAX_ITERATIONS) {
            throw new SaslException(sprintf(
                'The server iteration count of %d exceeds the maximum allowed of %d.',
                $iterations,
                self::MAX_ITERATIONS,
            ));
        }

        return [
            $fullNonce,
            $salt,
            $iterations
        ];
    }

    /**
     * Applies SASLprep to the password and derives the SCRAM SaltedPassword via PBKDF2.
     *
     * @throws SaslException if SASLprep rejects the password.
     */
    private function deriveSaltedPassword(
        string $password,
        string $salt,
        int $iterations,
    ): string {
        return $this->pbkdf2(
            SaslPrep::prepare($password),
            $salt,
            $iterations,
        );
    }

    /**
     * Decodes and verifies the client proof from the client-final-message.
     *
     * Returns true only when the base64 decoding succeeds and the proof matches.
     */
    private function isValidClientProof(
        Message $clientFinal,
        string $saltedPassword,
        string $authMessage,
    ): bool {
        $expectedProof = $this->makeClientProof(
            $saltedPassword,
            $authMessage,
        );
        $receivedProof = base64_decode(
            $clientFinal->getString('p'),
            true,
        );

        return $receivedProof !== false
            && hash_equals($expectedProof, $receivedProof);
    }

    /**
     * Computes the SCRAM SaltedPassword using PBKDF2.
     *
     *   SaltedPassword := Hi(Normalize(password), salt, i)
     */
    private function pbkdf2(
        string $password,
        string $salt,
        int $iterations,
    ): string {
        return hash_pbkdf2(
            $this->hashAlgorithm->value,
            $password,
            $salt,
            max(1, $iterations),
            0,
            true,
        );
    }

    /**
     * Computes an HMAC with the configured hash algorithm, returning raw bytes.
     */
    private function hmac(
        string $key,
        string $data,
    ): string {
        return hash_hmac(
            $this->hashAlgorithm->value,
            $data,
            $key,
            true,
        );
    }

    /**
     * Computes a hash with the configured hash algorithm, returning raw bytes.
     */
    private function hash(string $data): string
    {
        return hash(
            $this->hashAlgorithm->value,
            $data,
            true,
        );
    }

    private function makeClientProof(
        string $saltedPassword,
        string $authMessage,
    ): string {
        $clientKey = $this->hmac(
            $saltedPassword,
            self::HMAC_CLIENT_KEY
        );
        $storedKey = $this->hash($clientKey);
        $clientSignature = $this->hmac(
            $storedKey,
            $authMessage
        );

        return $clientKey ^ $clientSignature;
    }

    /**
     * RFC 5801 §4: cb-type = 1*(ALPHA / DIGIT / "." / "-"). Reject anything else to prevent
     * GS2 header injection (e.g. a type containing ',,' would corrupt the auth-message).
     *
     * @throws SaslException
     */
    private function validateCbindType(string $cbindType): void
    {
        if (preg_match('/^[A-Za-z0-9.\-]+$/', $cbindType) !== 1) {
            throw new SaslException(
                'The channel binding type contains invalid characters. ' .
                'Only alphanumeric characters, hyphens, and dots are permitted.',
            );
        }
    }
}
