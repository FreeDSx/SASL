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
 * Hash algorithms supported by SCRAM.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum HashAlgorithm: string
{
    case SHA1 = 'sha1';
    case SHA224 = 'sha224';
    case SHA256 = 'sha256';
    case SHA384 = 'sha384';
    case SHA512 = 'sha512';
    case SHA3_512 = 'sha3-512';
}
