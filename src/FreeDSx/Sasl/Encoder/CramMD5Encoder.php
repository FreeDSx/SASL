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
 * Responsible for encoding / decoding CRAM-MD5 messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class CramMD5Encoder implements EncoderInterface
{

    /**
     * {@inheritDoc}
     */
    public function encode(Message $message, SaslContext $context): string
    {
        if ($context->isServerMode()) {
            return $this->encodeServerChallenge($message);
        } else {
            return $this->encodeClientResponse($message);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function decode(string $data, SaslContext $context): Message
    {
        if ($context->isServerMode()) {
            return $this->decodeClientResponse($data);
        } else {
            return $this->decodeServerChallenge($data);
        }
    }

    /**
     * @throws SaslEncodingException
     */
    protected function encodeServerChallenge(Message $message): string
    {
        if (!$message->has('challenge')) {
            throw new SaslEncodingException('The server challenge message must contain a "challenge".');
        }
        $challenge = $message->get('challenge');

        return '<' . $challenge . '>';
    }

    /**
     * @throws SaslEncodingException
     */
    protected function encodeClientResponse(Message $message): string
    {
        if (!$message->has('username')) {
            throw new SaslEncodingException('The client response must contain a username.');
        }
        if (!$message->has('digest')) {
            throw new SaslEncodingException('The client response must contain a digest.');
        }
        $username = $message->get('username');
        $digest = $message->get('digest');

        if (!preg_match('/^[0-9a-f]{32}$/', $digest)) {
            throw new SaslEncodingException('The client digest must be a 16 octet, lower-case, hexadecimal value');
        }

        return $username . ' ' . $digest;
    }

    /**
     * @throws SaslEncodingException
     */
    protected function decodeServerChallenge(string $challenge): Message
    {
        if (!preg_match('/^<.*>$/', $challenge)) {
            throw new SaslEncodingException('The server challenge is malformed.');
        }

        return new Message(['challenge' => $challenge]);
    }

    /**
     * @throws SaslEncodingException
     */
    protected function decodeClientResponse(string $response): Message
    {
        if (!preg_match('/(.*) ([0-9a-f]{32})$/', $response, $matches)) {
            throw new SaslEncodingException('The client response is malformed.');
        }

        return new Message([
            'username' => $matches[1],
            'digest' => $matches[2],
        ]);
    }
}
