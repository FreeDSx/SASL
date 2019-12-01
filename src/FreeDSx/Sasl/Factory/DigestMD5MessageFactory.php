<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl\Factory;

use Exception;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Message;

/**
 * The DIGEST-MD5 Message Factory.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DigestMD5MessageFactory implements MessageFactoryInterface
{
    use NonceTrait;

    public const MESSAGE_CLIENT_RESPONSE = 1;

    public const MESSAGE_SERVER_CHALLENGE = 2;

    public const MESSAGE_SERVER_RESPONSE = 3;

    protected const CIPHER_LIST = [
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
    protected const NONCE_SIZE = 32;

    /**
     * @var bool
     */
    protected $hasOpenSsl;

    public function __construct()
    {
        $this->hasOpenSsl = extension_loaded('openssl');
    }

    /**
     * {@inheritDoc}
     */
    public function create(int $type, array $options = [], ?Message $received = null): Message
    {
        if ($type === self::MESSAGE_CLIENT_RESPONSE && $received !== null) {
            return $this->generateClientResponse($options, $received);
        } elseif ($type === self::MESSAGE_SERVER_RESPONSE) {
            return $this->generateServerResponse($options);
        } elseif ($type === self::MESSAGE_SERVER_CHALLENGE) {
            return $this->generateServerChallenge($options);
        } else {
            throw new SaslException(
                'Unable to generate message. Unrecognized message type / received message combination.'
            );
        }
    }

    protected function generateServerChallenge(array $options): Message
    {
        $challenge = new Message();
        $challenge->set('algorithm', 'md5-sess');
        $challenge->set('nonce', $options['nonce'] ?? $this->generateNonce($options['nonce_size'] ?? self::NONCE_SIZE));
        $challenge->set('qop', $this->generateAvailableQops($options));
        $challenge->set('realm', $options['realm'] ?? $_SERVER['USERDOMAIN'] ?? gethostname());
        $challenge->set('maxbuf', $options['maxbuf'] ?? '65536');
        $challenge->set('charset', 'utf-8');
        if (in_array('auth-conf', $challenge->get('qop'))) {
            $challenge->set('cipher', $this->getAvailableCiphers($options));
        }

        return $challenge;
    }

    protected function generateServerResponse(array $options): Message
    {
        $rspAuth = $options['rspauth'] ?? null;
        if ($rspAuth === null) {
            throw new SaslException('The server response must include the rspauth value.');
        }

        return new Message(['rspauth' => $rspAuth]);
    }

    /**
     * @throws SaslException
     */
    protected function generateClientResponse(array $options, Message $challenge): Message
    {
        $response = new Message();
        $qop = isset($options['qop']) ? (string) $options['qop'] : null;

        $response->set('algorithm', 'md5-sess');
        $response->set('nonce', $challenge->get('nonce'));
        $response->set('cnonce', $options['cnonce'] ?? $this->generateNonce($options['nonce_size'] ?? self::NONCE_SIZE));
        $response->set('nc', $options['nc'] ?? 1);
        $response->set('qop', $this->selectQopFromChallenge($challenge, $qop));
        $response->set('username', $options['username'] ?? $this->getCurrentUser());
        $response->set('realm', $options['realm'] ?? $this->getRealmFromChallenge($challenge));
        $response->set('digest-uri', $options['digest-uri'] ?? $this->getDigestUri($options, $response, $challenge));
        if ($response->get('qop') === 'auth-conf' && !$response->get('cipher')) {
            $this->setCipherForChallenge($options, $response, $challenge);
        }

        return $response;
    }

    /**
     * @throws SaslException
     */
    protected function getDigestUri(array $options, Message $response, Message $challenge): string
    {
        if (!isset($options['service'])) {
            throw new SaslException('If you do not supply a digest-uri, you must specify a service.');
        }

        return sprintf(
            '%s/%s',
            $options['service'],
            $response->get('realm')
        );
    }

    protected function generateAvailableQops(array $options): array
    {
        $qop = ['auth'];

        if (isset($options['use_integrity']) && $options['use_integrity'] === true) {
            $qop[] = 'auth-int';
        }
        if (isset($options['use_privacy']) && $options['use_privacy'] === true) {
            $qop[] = 'auth-conf';
        }

        return $qop;
    }

    /**
     * @throws SaslException
     */
    protected function selectQopFromChallenge(Message $challenge, ?string $qop): string
    {
        $available = (array) ($challenge->get('qop') ?? []);
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
            implode($available)
        ));
    }

    protected function getAvailableCiphers(array $options): array
    {
        $cipherList = self::CIPHER_LIST;

        # If specific cipher(s) are already wanted, filter the list...
        if (isset($options['cipher'])) {
            $wanted = (array) $options['cipher'];
            $cipherList = array_filter($cipherList, function ($name) use ($wanted) {
                return in_array($name, $wanted, true);
            });
        }

        # Now filter it based on what ciphers actually show as available in OpenSSL...
        $available = openssl_get_cipher_methods();
        foreach ($cipherList as $cipher => $name) {
            if (!in_array($cipher, $available, true)) {
                unset($cipherList[$cipher]);
            }
        }

        if (empty($cipherList)) {
            throw new SaslException('There are no available ciphers for auth-conf.');
        }

        return array_values($cipherList);
    }

    /**
     * @throws SaslException
     */
    protected function setCipherForChallenge(array $options, Message $response, Message $challenge): void
    {
        if (!$challenge->has('cipher')) {
            throw new SaslException('The client requested auth-conf, but the challenge contains no ciphers.');
        }
        $ciphers = $challenge->get('cipher');
        # If we are requesting a specific cipher, then only check that one...
        $toCheck = isset($options['cipher']) ? (array) $options['cipher'] : ['3des', 'des', 'rc4', 'rc4-56', 'rc4-40', ];

        $selected = null;
        foreach ($toCheck as $selection) {
            if (in_array($selection, $ciphers, true)) {
                $selected = $selection;
                break;
            }
        }
        if ($selected === null) {
            throw new SaslException(sprintf(
                'No recognized ciphers were offered in the challenge: %s',
                implode(', ', $ciphers)
            ));
        }

        $response->set('cipher', $selected);
    }

    protected function getCurrentUser(): string
    {
        if (isset($_SERVER['USERNAME'])) {
            return $_SERVER['USERNAME'];
        } elseif (isset($_SERVER['USER'])) {
            return $_SERVER['USER'];
        }

        throw new SaslException('Unable to determine a username for the response. You must supply a username.');
    }

    /**
     * Only populate if one realm is provided in the challenge. If more than one exists then the client must supply this.
     */
    protected function getRealmFromChallenge(Message $challenge): string
    {
        if (!$challenge->has('realm')) {
            throw new SaslException('Unable to determine a realm for the response.');
        }
        $realms = (array) $challenge->get('realm');
        $selected = array_pop($realms);

        return $selected;
    }
}
