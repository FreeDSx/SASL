<?php

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
use FreeDSx\Sasl\Encoder\EncoderInterface;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Factory\NonceTrait;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;

/**
 * The CRAM-MD5 challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class CramMD5Challenge implements ChallengeInterface
{
    use NonceTrait;

    /**
     * @var SaslContext
     */
    protected $context;

    /**
     * @var EncoderInterface
     */
    protected $encoder;

    public function __construct(bool $isServerMode = false)
    {
        $this->encoder = new CramMD5Encoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    /**
     * {@inheritDoc}
     */
    public function challenge(?string $received = null, array $options = []): SaslContext
    {
        $received = ($received === null) ? null : $this->encoder->decode($received, $this->context);

        if ($received === null) {
            !$this->context->isServerMode() ? $this->context : $this->generateServerChallenge($options);

            return $this->context;
        }

        if ($this->context->isServerMode()) {
            $this->validateClientResponse($received, $options);
        } else {
            $this->generateClientResponse($received, $options);
        }

        return $this->context;
    }

    protected function generateServerChallenge(array $options): SaslContext
    {
        $nonce = $options['challenge'] ?? $this->generateNonce(32);
        $challenge = new Message(['challenge' => $nonce]);
        $this->context->setResponse($this->encoder->encode($challenge, $this->context));
        $this->context->set('challenge', $challenge->get('challenge'));

        return $this->context;
    }

    protected function generateClientResponse(Message $received, array $options): void
    {
        if (!$received->has('challenge')) {
            throw new SaslException('Expected a server challenge to generate a client response.');
        }
        if (!(isset($options['username']) && isset($options['password']))) {
            throw new SaslException('A username and password is required for a client response.');
        }
        $response = new Message([
            'username' => $options['username'],
            'digest' => $this->generateDigest($received->get('challenge'), $options['password']),
        ]);
        $this->context->setResponse($this->encoder->encode($response, $this->context));
        $this->context->setIsComplete(true);
    }

    protected function validateClientResponse(Message $received, array $options): void
    {
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

    protected function generateDigest(string $challenge, string $key): string
    {
        return hash_hmac(
            'md5',
            $challenge,
            $key
        );
    }
}
