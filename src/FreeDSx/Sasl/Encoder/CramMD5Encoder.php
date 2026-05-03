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
 * Responsible for encoding / decoding CRAM-MD5 messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CramMD5Encoder implements EncoderInterface
{
    public function encode(
        Message $message,
        SaslContext $context,
    ): string {
        return $context->isServerMode()
            ? $this->encodeServerChallenge($message)
            : $this->encodeClientResponse($message);
    }

    public function decode(
        string $data,
        SaslContext $context,
    ): Message {
        return $context->isServerMode()
            ? $this->decodeClientResponse($data)
            : $this->decodeServerChallenge($data);
    }

    /**
     * @throws SaslEncodingException
     */
    private function encodeServerChallenge(Message $message): string
    {
        if (!$message->has('challenge')) {
            throw new SaslEncodingException('The server challenge message must contain a "challenge".');
        }

        return '<' . $message->get('challenge') . '>';
    }

    /**
     * @throws SaslEncodingException
     */
    private function encodeClientResponse(Message $message): string
    {
        if (!$message->has('username')) {
            throw new SaslEncodingException('The client response must contain a username.');
        }
        if (!$message->has('digest')) {
            throw new SaslEncodingException('The client response must contain a digest.');
        }
        $username = (string) $message->get('username');
        $digest = (string) $message->get('digest');

        if (preg_match('/^[0-9a-f]{32}$/', $digest) !== 1) {
            throw new SaslEncodingException('The client digest must be a 16 octet, lower-case, hexadecimal value');
        }

        return $username . ' ' . $digest;
    }

    /**
     * @throws SaslEncodingException
     */
    private function decodeServerChallenge(string $challenge): Message
    {
        if (preg_match('/^<.*>$/', $challenge) !== 1) {
            throw new SaslEncodingException('The server challenge is malformed.');
        }

        return new Message(['challenge' => $challenge]);
    }

    /**
     * @throws SaslEncodingException
     */
    private function decodeClientResponse(string $response): Message
    {
        if (preg_match('/(.*) ([0-9a-f]{32})$/', $response, $matches) !== 1) {
            throw new SaslEncodingException('The client response is malformed.');
        }

        return new Message([
            'username' => $matches[1],
            'digest' => $matches[2],
        ]);
    }
}
