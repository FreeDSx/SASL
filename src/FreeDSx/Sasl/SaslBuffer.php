<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl;

use FreeDSx\Sasl\Exception\SaslBufferException;
use FreeDSx\Sasl\Exception\SaslException;

/**
 * Helper functions to decode a SASL buffer when a security layer is installed. These can be used when receiving data
 * over the wire with a SASL security layer to determine whether or not the buffer is complete, and then unwrap the data.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SaslBuffer
{
    /**
     * Wraps the buffer by pre-pending the data length.
     */
    public static function wrap(string $data): string
    {
        return pack('N1', strlen($data)) . $data;
    }

    /**
     * Unwrap the buffer by removing pre-pended length and verifying we have enough data. Only the data is returned.
     *
     * @throws SaslBufferException
     * @throws SaslException
     */
    public static function unwrap(string $data): string
    {
        $length = strlen($data);
        if ($length < 4) {
            throw new SaslBufferException('Not enough data to unwrap the SASL buffer.');
        }
        $dataLength = $length - 4;
        $bufferLength = hexdec(bin2hex(substr($data, 0, 4)));
        if (!is_int($bufferLength)) {
            throw new SaslException('The buffer length exceeds the maximum allowed.');
        }
        if ($dataLength < $bufferLength) {
            throw new SaslBufferException('The SASL buffer is incomplete.');
        }

        return substr($data, 4, $bufferLength);
    }
}
