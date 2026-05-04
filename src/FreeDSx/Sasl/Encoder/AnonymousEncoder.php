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
 * Responsible for encoding / decoding ANONYMOUS messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AnonymousEncoder implements EncoderInterface
{
    public function encode(
        Message $message,
        SaslContext $context,
    ): string {
        if ($message->has('trace')) {
            return $message->getString('trace') ?? '';
        }

        return '';
    }

    public function decode(
        string $data,
        SaslContext $context,
    ): Message {
        $message = new Message();

        if ($data !== '') {
            $message->set('trace', $data);
        }

        return $message;
    }
}
