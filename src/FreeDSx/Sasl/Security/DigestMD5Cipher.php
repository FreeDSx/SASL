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

namespace FreeDSx\Sasl\Security;

/**
 * DIGEST-MD5 ciphers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum DigestMD5Cipher: string
{
    case THREE_DES = '3des';
    case DES = 'des';
    case RC4 = 'rc4';
    case RC4_40 = 'rc4-40';
    case RC4_56 = 'rc4-56';

    public function opensslName(): string
    {
        return match ($this) {
            self::THREE_DES => 'des-ede3-cbc',
            self::DES => 'des-ede-cbc',
            self::RC4 => 'rc4',
            self::RC4_40 => 'rc4-40',
            self::RC4_56 => 'rc4-56',
        };
    }

    public function blockSize(): int
    {
        return match ($this) {
            self::THREE_DES, self::DES => 8,
            self::RC4, self::RC4_40, self::RC4_56 => 1,
        };
    }

    /**
     * The "n" key length used to derive the encryption key from H(A1).
     */
    public function keyLength(): int
    {
        return match ($this) {
            self::THREE_DES, self::DES, self::RC4 => 16,
            self::RC4_40 => 5,
            self::RC4_56 => 7,
        };
    }
}
