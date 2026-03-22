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
use FreeDSx\Sasl\Challenge\ScramChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use FreeDSx\Sasl\SecurityStrength;

/**
 * A single class covering all SCRAM mechanism variants (RFC 5802 / RFC 7677).
 *
 * Instantiate with one of the NAME_* constants to select the variant:
 *
 *   new ScramMechanism(ScramMechanism::SHA256)
 *   new ScramMechanism(ScramMechanism::SHA256_PLUS)
 *
 * SCRAM does not define a post-authentication security layer; TLS is expected to
 * provide confidentiality and integrity instead.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ScramMechanism implements MechanismInterface
{
    public const SHA1 = 'SCRAM-SHA-1';
    public const SHA1_PLUS = 'SCRAM-SHA-1-PLUS';
    public const SHA224 = 'SCRAM-SHA-224';
    public const SHA224_PLUS = 'SCRAM-SHA-224-PLUS';
    public const SHA256 = 'SCRAM-SHA-256';
    public const SHA256_PLUS = 'SCRAM-SHA-256-PLUS';
    public const SHA384 = 'SCRAM-SHA-384';
    public const SHA384_PLUS = 'SCRAM-SHA-384-PLUS';
    public const SHA512 = 'SCRAM-SHA-512';
    public const SHA512_PLUS = 'SCRAM-SHA-512-PLUS';
    public const SHA3_512 = 'SCRAM-SHA3-512';
    public const SHA3_512_PLUS = 'SCRAM-SHA3-512-PLUS';

    public const VARIANTS = [
        self::SHA1,
        self::SHA1_PLUS,
        self::SHA224,
        self::SHA224_PLUS,
        self::SHA256,
        self::SHA256_PLUS,
        self::SHA384,
        self::SHA384_PLUS,
        self::SHA512,
        self::SHA512_PLUS,
        self::SHA3_512,
        self::SHA3_512_PLUS,
    ];

    /**
     * Maps SASL mechanism name to [php_hash_algorithm, channel_binding].
     *
     * The PHP algorithm names are used directly with hash(), hash_hmac(), and hash_pbkdf2().
     */
    private const MECHANISMS = [
        self::SHA1          => ['sha1', false],
        self::SHA1_PLUS     => ['sha1', true],
        self::SHA224        => ['sha224', false],
        self::SHA224_PLUS   => ['sha224', true],
        self::SHA256        => ['sha256', false],
        self::SHA256_PLUS   => ['sha256', true],
        self::SHA384        => ['sha384', false],
        self::SHA384_PLUS   => ['sha384', true],
        self::SHA512        => ['sha512', false],
        self::SHA512_PLUS   => ['sha512', true],
        self::SHA3_512      => ['sha3-512', false],
        self::SHA3_512_PLUS => ['sha3-512', true],
    ];

    /**
     * @var string
     */
    private $name;

    /**
     * @var string
     */
    private $hashAlgorithm;

    /**
     * @var bool
     */
    private $channelBinding;

    /**
     * @throws SaslException
     */
    public function __construct(string $name)
    {
        if (!isset(self::MECHANISMS[$name])) {
            throw new SaslException(sprintf(
                'The SCRAM variant "%s" is not supported. Supported variants: %s.',
                $name,
                implode(', ', array_keys(self::MECHANISMS))
            ));
        }

        $this->name = $name;
        [
            $this->hashAlgorithm,
            $this->channelBinding,
        ] = self::MECHANISMS[$name];
    }

    /**
     * {@inheritDoc}
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * {@inheritDoc}
     */
    public function challenge(bool $serverMode = false): ChallengeInterface
    {
        return new ScramChallenge(
            $serverMode,
            $this->hashAlgorithm,
            $this->channelBinding
        );
    }

    /**
     * {@inheritDoc}
     */
    public function securityStrength(): SecurityStrength
    {
        return new SecurityStrength(
            false,
            false,
            true,
            false,
            0
        );
    }

    /**
     * {@inheritDoc}
     *
     * SCRAM does not provide a post-authentication security layer.
     *
     * @throws SaslException
     */
    public function securityLayer(): SecurityLayerInterface
    {
        throw new SaslException(sprintf(
            'The %s mechanism does not provide a security layer.',
            $this->name
        ));
    }

    public function __toString(): string
    {
        return $this->name;
    }
}
