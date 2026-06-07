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

namespace FreeDSx\Sasl\Encoder;

use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;

/**
 * Encodes / decodes EXTERNAL messages. The payload is the optional authzId string (RFC 4422 §3.1).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ExternalEncoder implements EncoderInterface
{
    public function encode(
        Message $message,
        SaslContext $context,
    ): string {
        return $message->has('authzid')
            ? $message->getString('authzid')
            : '';
    }

    public function decode(
        string $data,
        SaslContext $context,
    ): Message {
        $message = new Message();

        if ($data !== '') {
            $message->set('authzid', $data);
        }

        return $message;
    }
}
