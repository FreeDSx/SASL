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
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\Options\CramMD5Options;
use FreeDSx\Sasl\SaslContext;

/**
 * The CRAM-MD5 challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CramMD5Challenge implements ChallengeInterface
{
    use NonceTrait;
    use ResolvesOptionsTrait;

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
        ?ChallengeOptionsInterface $options = null,
    ): SaslContext {
        $resolved = $this->resolveOptions(
            $options ?? new CramMD5Options(),
            CramMD5Options::class,
        );
        $message = $received === null ? null : $this->encoder->decode($received, $this->context);

        if ($message === null) {
            if ($this->context->isServerMode()) {
                $this->generateServerChallenge($resolved);
            }

            return $this->context;
        }

        if ($this->context->isServerMode()) {
            $this->validateClientResponse($message, $resolved);
        } else {
            $this->generateClientResponse($message, $resolved);
        }

        return $this->context;
    }

    private function generateServerChallenge(CramMD5Options $options): void
    {
        $nonce = $options->getChallenge() ?? $this->generateNonce(32);
        $challenge = new Message(['challenge' => $nonce]);
        $encoded = $this->encoder->encode($challenge, $this->context);
        $this->context->setResponse($encoded);
        # Store the encoded challenge string (e.g. "<nonce>") rather than the raw nonce. RFC 2195
        # requires the HMAC to be computed over the challenge exactly as the client received it.
        $this->context->set('challenge', $encoded);
    }

    /**
     * @throws SaslException
     */
    private function generateClientResponse(
        Message $received,
        CramMD5Options $options,
    ): void {
        if (!$received->has('challenge')) {
            throw new SaslException('Expected a server challenge to generate a client response.');
        }
        if ($options->getUsername() === null || $options->getPassword() === null) {
            throw new SaslException('A username and password is required for a client response.');
        }
        $response = new Message([
            'username' => $options->getUsername(),
            'digest' => $this->generateDigest($received->getString('challenge'), $options->getPassword()),
        ]);
        $this->context->setResponse($this->encoder->encode($response, $this->context));
        $this->context->setIsComplete(true);
    }

    /**
     * @throws SaslException
     */
    private function validateClientResponse(
        Message $received,
        CramMD5Options $options,
    ): void {
        if (!$received->has('username')) {
            throw new SaslException('The client response must have a username.');
        }
        if (!$received->has('digest')) {
            throw new SaslException('The client response must have a digest.');
        }
        if ($options->getPasswordCallback() === null) {
            throw new SaslException('To validate the client response you must supply the passwordCallback option.');
        }
        $username = $received->getString('username');
        $digest = $received->getString('digest');

        $expectedDigest = ($options->getPasswordCallback())($username, $this->context->getString('challenge'));

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
