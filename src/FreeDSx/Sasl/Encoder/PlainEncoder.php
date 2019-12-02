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
 * Responsible for encoding / decoding PLAIN messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PlainEncoder implements EncoderInterface
{
    /**
     * {@inheritDoc}
     */
    public function encode(Message $message, SaslContext $context): string
    {
        if (!$message->has('authzid')) {
            throw new SaslEncodingException('The PLAIN message must contain a authzid.');
        }
        if (!$message->has('authcid')) {
            throw new SaslEncodingException('The PLAIN message must contain a authzid.');
        }
        if (!$message->has('password')) {
            throw new SaslEncodingException('The PLAIN message must contain a password.');
        }
        $authzid = $this->validate($message->get('authzid'));
        $authcid = $this->validate($message->get('authcid'));
        $password = $this->validate($message->get('password'));

        return $authzid . "\x00" . $authcid . "\x00" . $password;
    }

    /**
     * {@inheritDoc}
     */
    public function decode(string $data, SaslContext $context): Message
    {
        if (preg_match('/^([^\x0]+)\x00([^\x0]+)\x00([^\x0]+)$/', $data, $matches) === 0) {
            throw new SaslEncodingException('The PLAIN message data is malformed.');
        }

        return new Message([
            'authzid' => $matches[1],
            'authcid' => $matches[2],
            'password' => $matches[3],
        ]);
    }

    protected function validate(string $data): string
    {
        if (strpos($data,"\x00") !== false) {
            throw new SaslEncodingException('PLAIN mechanism data cannot contain a null character.');
        }

        return $data;
    }
}
