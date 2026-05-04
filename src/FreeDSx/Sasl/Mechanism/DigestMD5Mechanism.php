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
final readonly class DigestMD5Mechanism implements MechanismInterface
{
    private const A2_SERVER = ':';

    private const A2_CLIENT = 'AUTHENTICATE:';

    public function getName(): MechanismName
    {
        return MechanismName::DIGEST_MD5;
    }

    public function challenge(bool $serverMode = false): ChallengeInterface
    {
        return new DigestMD5Challenge($serverMode);
    }

    public function securityStrength(): SecurityStrength
    {
        return new SecurityStrength(
            supportsIntegrity: true,
            supportsPrivacy: true,
            supportsAuth: true,
            isPlainTextAuth: false,
            maxKeySize: 128,
        );
    }

    public function securityLayer(): SecurityLayerInterface
    {
        return new DigestMD5SecurityLayer();
    }

    public function __toString(): string
    {
        return MechanismName::DIGEST_MD5->value;
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
    public static function computeResponse(
        string $password,
        Message $challenge,
        Message $response,
        bool $useServerMode = false,
    ): string {
        $a1 = self::computeA1($password, $challenge, $response);

        $qop = $response->getString('qop');
        $digestUri = $response->getString('digest-uri') ?? '';
        $a2 = $useServerMode ? self::A2_SERVER : self::A2_CLIENT;

        $a2 .= match ($qop) {
            'auth' => $digestUri,
            'auth-int', 'auth-conf' => $digestUri . ':00000000000000000000000000000000',
            default => throw new SaslException('The qop directive must be one of: auth, auth-conf, auth-int.'),
        };
        $a2 = hash('md5', $a2);

        return hash('md5', sprintf(
            '%s:%s:%s:%s:%s:%s',
            $a1,
            $challenge->getString('nonce') ?? '',
            str_pad(dechex($response->getIntOrParse('nc') ?? 0), 8, '0', STR_PAD_LEFT),
            $response->getString('cnonce') ?? '',
            $response->getString('qop') ?? '',
            $a2,
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
     */
    public static function computeA1(
        string $password,
        Message $challenge,
        Message $response,
    ): string {
        $a1 = hash('md5', sprintf(
            '%s:%s:%s',
            $response->getString('username') ?? '',
            $response->getString('realm') ?? '',
            $password,
        ), true);
        $a1 = sprintf(
            '%s:%s:%s',
            $a1,
            $challenge->getString('nonce') ?? '',
            $response->getString('cnonce') ?? '',
        );
        if ($response->has('authzid')) {
            $a1 .= ':' . ($response->getString('authzid') ?? '');
        }

        return hash('md5', $a1);
    }
}
