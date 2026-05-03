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

use FreeDSx\Sasl\Encoder\CramMD5Encoder;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Factory\NonceTrait;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;

/**
 * The CRAM-MD5 challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CramMD5Challenge implements ChallengeInterface
{
    use NonceTrait;

    private readonly SaslContext $context;

    private readonly CramMD5Encoder $encoder;

    public function __construct(bool $isServerMode = false)
    {
        $this->encoder = new CramMD5Encoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    public function challenge(
        ?string $received = null,
        array $options = [],
    ): SaslContext {
        $message = $received === null ? null : $this->encoder->decode($received, $this->context);

        if ($message === null) {
            if ($this->context->isServerMode()) {
                $this->generateServerChallenge($options);
            }

            return $this->context;
        }

        if ($this->context->isServerMode()) {
            $this->validateClientResponse($message, $options);
        } else {
            $this->generateClientResponse($message, $options);
        }

        return $this->context;
    }

    /**
     * @param array<string, mixed> $options
     */
    private function generateServerChallenge(array $options): void
    {
        $nonce = (string) ($options['challenge'] ?? $this->generateNonce(32));
        $challenge = new Message(['challenge' => $nonce]);
        $encoded = $this->encoder->encode($challenge, $this->context);
        $this->context->setResponse($encoded);
        # Store the encoded challenge string (e.g. "<nonce>") rather than the raw nonce. RFC 2195
        # requires the HMAC to be computed over the challenge exactly as the client received it.
        $this->context->set('challenge', $encoded);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws SaslException
     */
    private function generateClientResponse(
        Message $received,
        array $options,
    ): void {
        if (!$received->has('challenge')) {
            throw new SaslException('Expected a server challenge to generate a client response.');
        }
        if (!isset($options['username'], $options['password'])) {
            throw new SaslException('A username and password is required for a client response.');
        }
        $response = new Message([
            'username' => $options['username'],
            'digest' => $this->generateDigest((string) $received->get('challenge'), (string) $options['password']),
        ]);
        $this->context->setResponse($this->encoder->encode($response, $this->context));
        $this->context->setIsComplete(true);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws SaslException
     */
    private function validateClientResponse(
        Message $received,
        array $options,
    ): void {
        if (!$received->has('username')) {
            throw new SaslException('The client response must have a username.');
        }
        if (!$received->has('digest')) {
            throw new SaslException('The client response must have a digest.');
        }
        if (!isset($options['password'])) {
            throw new SaslException('To validate the client response you must supply the password option.');
        }
        $username = $received->get('username');
        $digest = $received->get('digest');

        $password = $options['password'];
        if (!is_callable($password)) {
            throw new SaslException('The password option must be callable. It will be passed the username and challenge');
        }
        $expectedDigest = $password($username, $this->context->get('challenge'));

        $this->context->setIsAuthenticated($expectedDigest === $digest);
        $this->context->setIsComplete(true);
    }

    private function generateDigest(
        string $challenge,
        string $key,
    ): string {
        return hash_hmac(
            'md5',
            $challenge,
            $key,
        );
    }
}
