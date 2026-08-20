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

use FreeDSx\Sasl\Exception\SaslEncodingException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;

/**
 * Encodes / decodes PLAIN messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PlainEncoder implements EncoderInterface
{
    /**
     * RFC 4616 2 makes the authzid optional, so an absent one is encoded as the leading NUL alone.
     */
    public function encode(
        Message $message,
        SaslContext $context,
    ): string {
        if (!$message->has('authcid')) {
            throw new SaslEncodingException('The PLAIN message must contain a authcid.');
        }
        if (!$message->has('password')) {
            throw new SaslEncodingException('The PLAIN message must contain a password.');
        }
        $authzid = $this->validate($message->getString('authzid'));
        $authcid = $this->validate($message->getString('authcid'));
        $password = $this->validate($message->getString('password'));

        return $authzid . "\x00" . $authcid . "\x00" . $password;
    }

    /**
     * The authzid is null when the client omitted it, which RFC 4616 2 has the server derive from the authcid.
     */
    public function decode(
        string $data,
        SaslContext $context,
    ): Message {
        if (preg_match('/^([^\x0]*)\x00([^\x0]+)\x00([^\x0]+)$/', $data, $matches) !== 1) {
            throw new SaslEncodingException('The PLAIN message data is malformed.');
        }

        return new Message([
            'authzid' => $matches[1] === '' ? null : $matches[1],
            'authcid' => $matches[2],
            'password' => $matches[3],
        ]);
    }

    private function validate(string $data): string
    {
        if (str_contains($data, "\x00")) {
            throw new SaslEncodingException('PLAIN mechanism data cannot contain a null character.');
        }

        return $data;
    }
}
