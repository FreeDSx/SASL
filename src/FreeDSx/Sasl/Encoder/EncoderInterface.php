<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl\Encoder;

use FreeDSx\Sasl\Exception\SaslEncodingException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;

/**
 * The SASL client.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface EncoderInterface
{
    /**
     * Encode a message object to a string. Optionally pass the type of message to be encoded.
     *
     * @throws SaslEncodingException
     */
    public function encode(Message $message, SaslContext $context): string;

    /**
     * Decode a string to a message object. Optionally pass the type of message to be decoded.
     *
     * @throws SaslEncodingException
     */
    public function decode(string $data, SaslContext $context): Message;
}
