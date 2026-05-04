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

namespace FreeDSx\Sasl\Factory;

use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\Security\DigestMD5Cipher;

/**
 * The DIGEST-MD5 Message Factory.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DigestMD5MessageFactory implements MessageFactoryInterface
{
    use NonceTrait;

    /**
     * Maps the supported OpenSSL cipher names to the SASL cipher wire names.
     */
    private const OPENSSL_TO_SASL_CIPHERS = [
        'rc4' => 'rc4',
        'des-ede-cbc' => 'des',
        'des-ede3-cbc' => '3des',
        'rc4-40' => 'rc4-40',
        'rc4-56' => 'rc4-56',
    ];

    /**
     * Per the RFC:
     *
     *   It is RECOMMENDED that it contain at least 64 bits of entropy
     *
     * Byte length represented here. Bumping it up quite a bit from the recommendation. Can be controlled via an option.
     */
    private const NONCE_SIZE = 32;

    public function create(
        DigestMD5MessageType $type,
        array $options = [],
        ?Message $received = null,
    ): Message {
        return match (true) {
            $type === DigestMD5MessageType::CLIENT_RESPONSE && $received !== null
                => $this->generateClientResponse($options, $received),
            $type === DigestMD5MessageType::SERVER_RESPONSE
                => $this->generateServerResponse($options),
            $type === DigestMD5MessageType::SERVER_CHALLENGE
                => $this->generateServerChallenge($options),
            default => throw new SaslException(
                'Unable to generate message. Unrecognized message type / received message combination.',
            ),
        };
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws SaslException
     */
    private function generateServerChallenge(array $options): Message
    {
        $challenge = new Message();
        $nonceSize = is_int($options['nonce_size'] ?? null) ? $options['nonce_size'] : self::NONCE_SIZE;
        $challenge->set('algorithm', 'md5-sess');
        $challenge->set('nonce', $options['nonce'] ?? $this->generateNonce($nonceSize));
        $challenge->set('qop', $this->generateAvailableQops($options));
        $challenge->set('realm', $options['realm'] ?? $_SERVER['USERDOMAIN'] ?? gethostname());
        $challenge->set('maxbuf', $options['maxbuf'] ?? '65536');
        $challenge->set('charset', 'utf-8');
        if (in_array('auth-conf', (array) $challenge->get('qop'), true)) {
            $challenge->set('cipher', $this->getAvailableCiphers($options));
        }

        return $challenge;
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws SaslException
     */
    private function generateServerResponse(array $options): Message
    {
        $rspAuth = $options['rspauth'] ?? null;
        if ($rspAuth === null) {
            throw new SaslException('The server response must include the rspauth value.');
        }

        return new Message(['rspauth' => $rspAuth]);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws SaslException
     */
    private function generateClientResponse(
        array $options,
        Message $challenge,
    ): Message {
        $response = new Message();
        $qop = is_string($options['qop'] ?? null) ? $options['qop'] : null;

        $response->set('algorithm', 'md5-sess');
        $response->set('nonce', $challenge->get('nonce'));
        $cnNonceSize = is_int($options['nonce_size'] ?? null) ? $options['nonce_size'] : self::NONCE_SIZE;
        $response->set('cnonce', $options['cnonce'] ?? $this->generateNonce($cnNonceSize));
        $response->set('nc', $options['nc'] ?? 1);
        $response->set('qop', $this->selectQopFromChallenge($challenge, $qop));
        $response->set('username', $options['username'] ?? $this->getCurrentUser());
        $response->set('realm', $options['realm'] ?? $this->getRealmFromChallenge($challenge));
        $response->set('digest-uri', $options['digest-uri'] ?? $this->getDigestUri($options, $response));
        if ($response->get('qop') === 'auth-conf' && $response->get('cipher') === null) {
            $this->setCipherForChallenge($options, $response, $challenge);
        }

        return $response;
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws SaslException
     */
    private function getDigestUri(
        array $options,
        Message $response,
    ): string {
        if (!isset($options['service'])) {
            throw new SaslException('If you do not supply a digest-uri, you must specify a service.');
        }

        return sprintf(
            '%s/%s',
            is_string($options['service'] ?? null) ? $options['service'] : '',
            $response->getString('realm') ?? '',
        );
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return string[]
     */
    private function generateAvailableQops(array $options): array
    {
        $qop = ['auth'];

        if (($options['use_integrity'] ?? false) === true) {
            $qop[] = 'auth-int';
        }
        if (($options['use_privacy'] ?? false) === true) {
            $qop[] = 'auth-conf';
        }

        return $qop;
    }

    /**
     * @throws SaslException
     */
    private function selectQopFromChallenge(
        Message $challenge,
        ?string $qop,
    ): string {
        $available = $challenge->getStringArray('qop') ?? [];
        /* Per the RFC: This directive is optional; if not present it defaults to "auth". */
        if (count($available) === 0) {
            return 'auth';
        }
        $options = $qop !== null ? [$qop] : ['auth-conf', 'auth-int', 'auth'];

        foreach ($options as $method) {
            if (in_array($method, $available, true)) {
                return $method;
            }
        }

        throw new SaslException(sprintf(
            'None of the qop values are recognized, or the one you selected is not available. Available methods are: %s',
            implode(', ', $available),
        ));
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return string[]
     *
     * @throws SaslException
     */
    private function getAvailableCiphers(array $options): array
    {
        $cipherList = self::OPENSSL_TO_SASL_CIPHERS;

        # If specific cipher(s) are already wanted, filter the list...
        if (isset($options['cipher'])) {
            $wanted = (array) $options['cipher'];
            $cipherList = array_filter(
                $cipherList,
                static fn (string $name): bool => in_array($name, $wanted, true),
            );
        }

        # Now filter it based on what ciphers actually show as available in OpenSSL...
        $available = openssl_get_cipher_methods();
        foreach ($cipherList as $cipher => $name) {
            if (!in_array($cipher, $available, true)) {
                unset($cipherList[$cipher]);
            }
        }

        if (count($cipherList) === 0) {
            throw new SaslException('There are no available ciphers for auth-conf.');
        }

        return array_values($cipherList);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @throws SaslException
     */
    private function setCipherForChallenge(
        array $options,
        Message $response,
        Message $challenge,
    ): void {
        if (!$challenge->has('cipher')) {
            throw new SaslException('The client requested auth-conf, but the challenge contains no ciphers.');
        }
        $ciphers = $challenge->getStringArray('cipher') ?? [];
        # If we are requesting a specific cipher, then only check that one...
        $toCheck = isset($options['cipher'])
            ? (array) $options['cipher']
            : array_map(static fn (DigestMD5Cipher $c): string => $c->value, [
                DigestMD5Cipher::THREE_DES,
                DigestMD5Cipher::DES,
                DigestMD5Cipher::RC4,
                DigestMD5Cipher::RC4_56,
                DigestMD5Cipher::RC4_40,
            ]);

        $selected = null;
        foreach ($toCheck as $selection) {
            if (is_string($selection) && in_array($selection, $ciphers, true)) {
                $selected = $selection;
                break;
            }
        }
        if ($selected === null) {
            throw new SaslException(sprintf(
                'No recognized ciphers were offered in the challenge: %s',
                implode(', ', $ciphers),
            ));
        }

        $response->set('cipher', $selected);
    }

    /**
     * @throws SaslException
     */
    private function getCurrentUser(): string
    {
        if (is_string($_SERVER['USERNAME'] ?? null)) {
            return $_SERVER['USERNAME'];
        }
        if (is_string($_SERVER['USER'] ?? null)) {
            return $_SERVER['USER'];
        }

        throw new SaslException('Unable to determine a username for the response. You must supply a username.');
    }

    /**
     * Only populate if one realm is provided in the challenge. If more than one exists then the client must supply this.
     *
     * @throws SaslException
     */
    private function getRealmFromChallenge(Message $challenge): string
    {
        $realm = $challenge->getString('realm');
        if ($realm === null) {
            throw new SaslException('Unable to determine a realm for the response.');
        }

        return $realm;
    }
}
