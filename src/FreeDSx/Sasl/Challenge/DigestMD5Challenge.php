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

use FreeDSx\Sasl\Encoder\DigestMD5Encoder;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Factory\DigestMD5MessageFactory;
use FreeDSx\Sasl\Factory\DigestMD5MessageType;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\Options\DigestMD5Options;
use FreeDSx\Sasl\SaslContext;

/**
 * The DIGEST-MD5 challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DigestMD5Challenge implements ChallengeInterface
{
    use ResolvesOptionsTrait;

    private readonly SaslContext $context;

    private readonly DigestMD5MessageFactory $factory;

    private readonly DigestMD5Encoder $encoder;

    private ?Message $challenge = null;

    public function __construct(bool $isServerMode = false)
    {
        $this->factory = new DigestMD5MessageFactory();
        $this->encoder = new DigestMD5Encoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    public function challenge(
        ?string $received = null,
        ?ChallengeOptionsInterface $options = null,
    ): SaslContext {
        $resolved = $this->resolveOptions(
            $options ?? new DigestMD5Options(),
            DigestMD5Options::class,
        );

        $message = $received === null ? null : $this->encoder->decode($received, $this->context);
        $response = $this->context->isServerMode()
            ? $this->generateServerResponse($message, $resolved)
            : $this->generateClientResponse($message, $resolved);
        $this->context->setResponse($response);

        return $this->context;
    }

    /**
     * @throws SaslException
     */
    private function generateClientResponse(
        ?Message $message,
        DigestMD5Options $options,
    ): ?string {
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
            $this->context->setHasSecurityLayer($options->isUseIntegrity() || $options->isUsePrivacy());
        }
        if ($this->context->hasSecurityLayer()) {
            $this->context->set('seqnumsnt', 0);
            $this->context->set('seqnumrcv', 0);
        }
        $this->context->setIsComplete($message->has('rspauth'));

        return null;
    }

    /**
     * @throws SaslException
     */
    private function generateServerResponse(
        ?Message $received,
        DigestMD5Options $options,
    ): ?string {
        $response = $received === null
            ? $this->generateServerChallenge($options)
            : $this->generateServerVerification($received, $options);

        return $response === null ? null : $this->encoder->encode($response, $this->context);
    }

    private function isClientChallengeNeeded(Message $message): bool
    {
        if ($this->context->isServerMode()) {
            return false;
        }

        return $message->get('rspauth') === null;
    }

    /**
     * @throws SaslException
     */
    private function createClientResponse(
        Message $message,
        DigestMD5Options $options,
    ): string {
        $password = $options->getPassword() ?? '';

        $qop = match (true) {
            $options->isUsePrivacy() => 'auth-conf',
            $options->isUseIntegrity() => 'auth-int',
            default => 'auth',
        };
        $this->context->set('qop', $qop);

        $messageOpts = [
            'username' => $options->getUsername(),
            'digest-uri' => $options->getHost() !== null ? ($options->getService() . '/' . $options->getHost()) : null,
            'qop' => $qop,
            'nonce_size' => $options->getNonceSize(),
            'service' => $options->getService(),
        ];
        if ($options->getCnonce() !== null) {
            $messageOpts['cnonce'] = $options->getCnonce();
        }
        if ($options->getNonce() !== null) {
            $messageOpts['nonce'] = $options->getNonce();
        }
        if ($options->getCipher() !== null) {
            $messageOpts['cipher'] = $options->getCipher();
        }
        $response = $this->factory->create(
            DigestMD5MessageType::CLIENT_RESPONSE,
            $messageOpts,
            $message,
        );
        $response->set('response', DigestMD5Mechanism::computeResponse(
            $password,
            $message,
            $response,
            $this->context->isServerMode(),
        ));

        # The verification is used to check the response value returned from the server for authentication.
        $this->context->set(
            'verification',
            DigestMD5Mechanism::computeResponse(
                $password,
                $message,
                $response,
                !$this->context->isServerMode(),
            ),
        );

        # The A1 / cipher value is used in the security layer.
        if ($options->isUseIntegrity() || $options->isUsePrivacy()) {
            $this->context->set('a1', hex2bin(DigestMD5Mechanism::computeA1($password, $message, $response)));
            $this->context->set('cipher', $response->get('cipher'));
        }

        return $this->encoder->encode($response, $this->context);
    }

    /**
     * @throws SaslException
     */
    private function generateServerVerification(
        Message $received,
        DigestMD5Options $options,
    ): ?Message {
        $this->context->setIsComplete(true);
        # The client sent a response without us sending a challenge...
        if ($this->challenge === null) {
            return null;
        }

        # @todo This should accept some kind of computed value, like the a1. Then it could generate the other values
        #       using that.
        $password = $options->getPassword();
        $qop = $received->getString('qop');
        $cipher = $received->getString('cipher');
        if ($password === null) {
            return null;
        }
        # Client selected a qop we did not advertise...
        if (!in_array($qop, $this->challenge->getStringArray('qop') ?? [], true)) {
            return null;
        }
        # Client selected a cipher we did not advertise...
        if (!in_array($cipher, $this->challenge->getStringArray('cipher') ?? [], true)) {
            return null;
        }
        # The client sent a nonce without the minimum length from the RFC...
        if (strlen($received->getString('cnonce')) < 12) {
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

        $response = DigestMD5Mechanism::computeResponse((string) $password, $this->challenge, $received, true);
        $this->context->setIsAuthenticated(true);
        if ($qop === 'auth-int' || $qop === 'auth-conf') {
            $this->context->setHasSecurityLayer(true);
            $this->context->set('a1', hex2bin(DigestMD5Mechanism::computeA1((string) $password, $this->challenge, $received)));
            $this->context->set('cipher', $received->get('cipher'));
            $this->context->set('seqnumsnt', 0);
            $this->context->set('seqnumrcv', 0);
        }

        return $this->factory->create(
            DigestMD5MessageType::SERVER_RESPONSE,
            ['rspauth' => $response],
        );
    }

    /**
     * @throws SaslException
     */
    private function generateServerChallenge(DigestMD5Options $options): Message
    {
        $this->challenge = $this->factory->create(
            DigestMD5MessageType::SERVER_CHALLENGE,
            [
                'use_integrity' => $options->isUseIntegrity(),
                'use_privacy'   => $options->isUsePrivacy(),
                'nonce'         => $options->getNonce(),
                'nonce_size'    => $options->getNonceSize(),
                'realm'         => $options->getRealm(),
                'maxbuf'        => $options->getMaxbuf(),
                'cipher'        => $options->getCipher(),
            ],
        );

        return $this->challenge;
    }
}
