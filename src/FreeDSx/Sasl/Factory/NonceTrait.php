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

/**
 * Used to generate a nonce value.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait NonceTrait
{
    /**
     * From DIGEST-MD5:
     *
     * The cnonce-value is an opaque quoted string value provided by the client and used by both client and server to
     * avoid chosen plaintext attacks, and to provide mutual authentication. The security of the implementation depends
     * on a good choice. It is RECOMMENDED that it contain at least 64 bits of entropy.
     *
     * @throws SaslException
     */
    protected function generateNonce(int $byteLength): string
    {
        try {
            return base64_encode(random_bytes($byteLength));
        } catch (Exception $e) {
            throw new SaslException(sprintf(
                'Unable to generate the nonce: %s',
                $e->getMessage()
            ), $e->getCode(), $e);
        }
    }
}