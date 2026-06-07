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

/**
 * SASL mechanism names.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum MechanismName: string
{
    case ANONYMOUS = 'ANONYMOUS';
    case EXTERNAL = 'EXTERNAL';
    case PLAIN = 'PLAIN';
    case CRAM_MD5 = 'CRAM-MD5';
    case DIGEST_MD5 = 'DIGEST-MD5';
    case SCRAM_SHA1 = 'SCRAM-SHA-1';
    case SCRAM_SHA1_PLUS = 'SCRAM-SHA-1-PLUS';
    case SCRAM_SHA224 = 'SCRAM-SHA-224';
    case SCRAM_SHA224_PLUS = 'SCRAM-SHA-224-PLUS';
    case SCRAM_SHA256 = 'SCRAM-SHA-256';
    case SCRAM_SHA256_PLUS = 'SCRAM-SHA-256-PLUS';
    case SCRAM_SHA384 = 'SCRAM-SHA-384';
    case SCRAM_SHA384_PLUS = 'SCRAM-SHA-384-PLUS';
    case SCRAM_SHA512 = 'SCRAM-SHA-512';
    case SCRAM_SHA512_PLUS = 'SCRAM-SHA-512-PLUS';
    case SCRAM_SHA3_512 = 'SCRAM-SHA3-512';
    case SCRAM_SHA3_512_PLUS = 'SCRAM-SHA3-512-PLUS';

    public function isScram(): bool
    {
        return str_starts_with(
            $this->value,
            'SCRAM-',
        );
    }

    public function isChannelBinding(): bool
    {
        return str_ends_with(
            $this->value,
            '-PLUS',
        );
    }

    /**
     * The hash algorithm backing this SCRAM variant, or null for non-SCRAM mechanisms.
     */
    public function hashAlgorithm(): ?HashAlgorithm
    {
        return match ($this) {
            self::SCRAM_SHA1, self::SCRAM_SHA1_PLUS => HashAlgorithm::SHA1,
            self::SCRAM_SHA224, self::SCRAM_SHA224_PLUS => HashAlgorithm::SHA224,
            self::SCRAM_SHA256, self::SCRAM_SHA256_PLUS => HashAlgorithm::SHA256,
            self::SCRAM_SHA384, self::SCRAM_SHA384_PLUS => HashAlgorithm::SHA384,
            self::SCRAM_SHA512, self::SCRAM_SHA512_PLUS => HashAlgorithm::SHA512,
            self::SCRAM_SHA3_512, self::SCRAM_SHA3_512_PLUS => HashAlgorithm::SHA3_512,
            default => null,
        };
    }
}
