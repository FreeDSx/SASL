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

use FreeDSx\Sasl\Encoder\DigestMD5Encoder;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Factory\DigestMD5MessageFactory;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;

/**
 * The DIGEST-MD5 challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DigestMD5Challenge implements ChallengeInterface
{
    /**
     * @var array
     */
    protected const DEFAULTS = [
        'use_integrity' => false,
        'use_privacy' => false,
        'service' => 'ldap',
        'nonce_size' => null,
    ];

    /**
     * @var SaslContext
     */
    protected $context;

    /**
     * @var DigestMD5MessageFactory
     */
    protected $factory;

    /**
     * @var DigestMD5Encoder
     */
    protected $encoder;

    /**
     * @var null|Message
     */
    protected $challenge;

    public function __construct(bool $isServerMode = false)
    {
        $this->factory = new DigestMD5MessageFactory();
        $this->encoder = new DigestMD5Encoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    /**
     * {@inheritDoc}
     */
    public function challenge(?string $received = null, array $options = []): SaslContext
    {
        $options = $options + self::DEFAULTS;

        $received = $received === null ? null : $this->encoder->decode($received, $this->context);
        if ($this->context->isServerMode()) {
            $response = $this->generateServerResponse($received, $options);
        } else {
            $response = $this->generateClientResponse($received, $options);
        }
        $this->context->setResponse($response);

        return $this->context;
    }

    /**
     * @throws SaslException
     */
    protected function generateClientResponse(?Message $message, $options): ?string
    {
        if ($message === null) {
            return null;
        }
        if ($this->isClientChallengeNeeded($message)) {
            return $this->createClientResponse($message, $options);
        }

        if ($message->has('rspauth') && $this->context->get('verification') === null) {
            throw new SaslException('The rspauth value was received before the response was generated.');
        }
        if ($message->has('rspauth') && $message->get('rspauth') === $this->context->get('verification')) {
            $this->context->setIsAuthenticated(true);
            $this->context->setHasSecurityLayer($options['use_integrity'] || $options['use_privacy']);
        }
        if ($this->context->hasSecurityLayer()) {
            $this->context->set('seqnumsnt', 0);
            $this->context->set('seqnumrcv', 0);
        }
        $this->context->setIsComplete($message->has('rspauth'));

        return null;
    }

    protected function generateServerResponse(?Message $received, array $options): ?string
    {
        if ($received === null) {
            $response = $this->generateServerChallenge($options);
        } else {
            $response = $this->generateServerVerification($received, $options);
        }

        return $response === null ? null : $this->encoder->encode($response, $this->context);
    }

    protected function isClientChallengeNeeded(Message $message): bool
    {
        if ($this->context->isServerMode()) {
            return false;
        }

        return $message->get('rspauth') === null;
    }

    /**
     * @throws SaslException
     */
    protected function createClientResponse(Message $message, array $options): string
    {
        $password = $options['password'] ?? '';

        if ($options['use_privacy']) {
            $this->context->set('qop', 'auth-conf');
        } elseif ($options['use_integrity']) {
            $this->context->set('qop', 'auth-int');
        } else {
            $this->context->set('qop', 'auth');
        }

        $messageOpts = [
            'username' => $options['username'] ?? null,
            'digest-uri' => isset($options['host']) ? ($options['service'] . '/' . $options['host']) : null,
            'qop' => $this->context->get('qop'),
            'nonce_size' => $options['nonce_size'],
            'service' => $options['service']
        ];
        if (isset($options['cnonce'])) {
            $messageOpts['cnonce'] = $options['cnonce'];
        }
        if (isset($options['nonce'])) {
            $messageOpts['nonce'] = $options['nonce'];
        }
        if (isset($options['cipher'])) {
            $messageOpts['cipher'] = $options['cipher'];
        }
        $response = $this->factory->create(
            DigestMD5MessageFactory::MESSAGE_CLIENT_RESPONSE, $messageOpts, $message
        );
        $response->set('response', DigestMD5Mechanism::computeResponse(
            $password,
            $message,
            $response,
            $this->context->isServerMode()
        ));

        # The verification is used to check the response value returned from the server for authentication.
        $this->context->set(
            'verification',
            DigestMD5Mechanism::computeResponse(
                $password,
                $message,
                $response,
                !$this->context->isServerMode()
            )
        );

        # Pre-compute some stuff in advance. The A1 / cipher value is used in the security layer.
        if ($options['use_integrity'] || $options['use_privacy']) {
            $this->context->set('a1', hex2bin(DigestMD5Mechanism::computeA1($password, $message, $response)));
            $this->context->set('cipher', $response->get('cipher'));
        }

        return $this->encoder->encode($response, $this->context);
    }

    protected function generateServerVerification(Message $received, array $options): ?Message
    {
        $this->context->setIsComplete(true);
        # The client sent a response without us sending a challenge...
        if ($this->challenge === null) {
            return null;
        }

        # @todo This should accept some kind of computed value, like the a1. Then it could generate the other values
        #       using that.
        $password = $options['password'] ?? null;
        $qop = $received->get('qop');
        $cipher = $received->get('cipher');
        if ($password === null) {
            return null;
        }
        # Client selected a qop we did not advertise...
        if (!in_array($qop, $this->challenge->get('qop'), true)) {
            return null;
        }
        # Client selected a cipher we did not advertise...
        if (!in_array($cipher, $this->challenge->get('cipher'), true)) {
            return null;
        }
        # The client sent a nonce without the minimum length from the RFC...
        if (strlen((string) $received->get('cnonce')) < 12) {
            return null;
        }
        # The client sent back a nonce different than what we sent them...
        if ($received->get('nonce') !== $this->challenge->get('nonce')) {
            return null;
        }

        # Generate our own response to compare against what we received from the client. If they do not match,
        # then the password was incorrect.
        $expected = DigestMD5Mechanism::computeResponse($password, $this->challenge, $received);
        if ($expected !== $received->get('response')) {
            return null;
        }

        $response = DigestMD5Mechanism::computeResponse($password, $this->challenge, $received, true);
        $this->context->setIsAuthenticated(true);
        if ($qop === 'auth-int' || $qop === 'auth-conf') {
            $this->context->setHasSecurityLayer(true);
            $this->context->set('a1', hex2bin(DigestMD5Mechanism::computeA1($password, $this->challenge, $received)));
            $this->context->set('cipher', $received->get('cipher'));
            $this->context->set('seqnumsnt', 0);
            $this->context->set('seqnumrcv', 0);
        }

        return $this->factory->create(
            DigestMD5MessageFactory::MESSAGE_SERVER_RESPONSE,
            ['rspauth' => $response]
        );
    }

    protected function generateServerChallenge(array $options): Message
    {
        $messageOpts = [];
        if (isset($options['nonce'])) {
            $messageOpts['nonce'] = $options['nonce'];
        }
        if (isset($options['cipher'])) {
            $messageOpts['cipher'] = $options['cipher'];
        }
        $this->challenge = $this->factory->create(
            DigestMD5MessageFactory::MESSAGE_SERVER_CHALLENGE, $options
        );

        return $this->challenge;
    }
}
