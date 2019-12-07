<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl\Mechanism;

use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\Challenge\DigestMD5Challenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\Security\DigestMD5SecurityLayer;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use FreeDSx\Sasl\SecurityStrength;

/**
 * The Digest-MD5 mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DigestMD5Mechanism implements MechanismInterface
{
    public const NAME = 'DIGEST-MD5';

    protected const A2_SERVER = ':';

    protected const A2_CLIENT = 'AUTHENTICATE:';

    /**
     * {@inheritDoc}
     */
    public function getName(): string
    {
        return self::NAME;
    }

    /**
     * {@inheritDoc}
     */
    public function challenge(): ChallengeInterface
    {
        $challenge = new DigestMD5Challenge();

        return $challenge;
    }

    /**
     * {@inheritDoc}
     */
    public function securityStrength(): SecurityStrength
    {
        return new SecurityStrength(
            true,
            true,
            true,
            false,
            128
        );
    }

    /**
     * {@inheritDoc}
     */
    public function securityLayer(): SecurityLayerInterface
    {
        return new DigestMD5SecurityLayer();
    }

    public function __toString()
    {
        return self::NAME;
    }

    /**
     * Generates the computed response value. RFC2831 2.1.2.1
     *
     *  HEX( KD ( HEX(H(A1)),
     *      { nonce-value, ":" nc-value, ":",
     *        cnonce-value, ":", qop-value, ":", HEX(H(A2)) }))
     *
     * If the "qop" directive's value is "auth", then A2 is:
     *
     *   A2 = { "AUTHENTICATE:", digest-uri-value }
     *
     * If the "qop" value is "auth-int" or "auth-conf" then A2 is:
     *
     *   A2 = { "AUTHENTICATE:", digest-uri-value,
     *      ":00000000000000000000000000000000" }
     *
     * If this is the server context, then the beginning of A2 is just a semi-colon.
     *
     * @throws SaslException
     */
    public static function computeResponse(string $password, Message $challenge, Message $response, bool $useServerMode = false): string
    {
        $a1 = self::computeA1($password, $challenge, $response);

        $qop = $response->get('qop');
        $digestUri = $response->get('digest-uri');
        $a2 = $useServerMode ? self::A2_SERVER : self::A2_CLIENT;

        if ($qop === 'auth') {
            $a2 .= $digestUri;
        } elseif ($qop === 'auth-int' || $qop === 'auth-conf') {
            $a2 .= $digestUri . ':00000000000000000000000000000000';
        } else {
            throw new SaslException('The qop directive must be one of: auth, auth-conf, auth-int.');
        }
        $a2 = hash('md5', $a2);

        return hash('md5', sprintf(
            '%s:%s:%s:%s:%s:%s',
            $a1,
            $challenge->get('nonce'),
            str_pad(dechex($response->get('nc')), 8, '0', STR_PAD_LEFT),
            $response->get('cnonce'),
            $response->get('qop'),
            $a2
        ));
    }

    /**
     * If authzid is specified, then A1 is
     *
     *   A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
     *        ":", nonce-value, ":", cnonce-value, ":", authzid-value }
     *
     * If authzid is not specified, then A1 is
     *
     *   A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
     *        ":", nonce-value, ":", cnonce-value }
     *
     */
    public static function computeA1(string $password, Message $challenge, Message $response): string
    {
        $a1 = hash('md5', sprintf(
            '%s:%s:%s',
            $response->get('username'),
            $response->get('realm'),
            $password
        ), true);
        $a1 = sprintf(
            '%s:%s:%s',
            $a1,
            $challenge->get('nonce'),
            $response->get('cnonce')
        );
        if ($response->has('authzid')) {
            $a1 .= ':' . $response->get('authzid');
        }

        return hash('md5', $a1);
    }
}
