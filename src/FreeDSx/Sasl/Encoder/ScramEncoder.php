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
 * Encodes / decodes SCRAM messages (RFC 5802).
 *
 * SCRAM wire format is comma-separated attr=value pairs. The client-first-message is prefixed by
 * a GS2 header ('n,,', 'y,,', or 'p=type,,') before the client-first-message-bare.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ScramEncoder implements EncoderInterface
{
    /**
     * Matches the GS2 header at the start of a client-first-message: gs2-cbind-flag "," [authzid] ",".
     *
     * Formats: 'n,,', 'y,,', 'p=<cbtype>,,', optionally carrying an authzid: 'n,a=<authzid>,'.
     */
    private const MATCH_GS2_HEADER = '/^(n|y|p=[^,]*),(a=[^,]*)?,(.*)$/';

    /**
     * Message key under which the raw GS2 header bytes are stored.
     */
    private const GS2_HEADER = 'gs2-header';

    /**
     * Encodes a Message into a SCRAM comma-separated attr=value string.
     */
    public function encode(
        Message $message,
        SaslContext $context,
    ): string {
        $parts = [];
        foreach (array_keys($message->toArray()) as $attr) {
            $parts[] = $attr . '=' . ($message->getString($attr));
        }

        return implode(',', $parts);
    }

    /**
     * Decodes a SCRAM message string into a Message object.
     *
     * For client-first-messages the GS2 header is extracted and stored under the
     * 'gs2-header' key, and the remainder is parsed as attr=value pairs.
     *
     * @throws SaslEncodingException
     */
    public function decode(
        string $data,
        SaslContext $context,
    ): Message {
        $message = new Message();
        $data = $this->stripGs2Header($data, $message);

        # SCRAM attr values are printable ASCII excluding comma, so splitting on comma is safe.
        $parts = explode(',', $data);
        foreach ($parts as $part) {
            $eqPos = strpos($part, '=');
            if ($eqPos === false) {
                throw new SaslEncodingException(sprintf(
                    'Malformed SCRAM message attribute (no "=" separator found): "%s".',
                    $part,
                ));
            }

            $attr = substr($part, 0, $eqPos);
            # The value may itself contain '=' (e.g. base64 padding), so we only split on the first '='.
            $value = substr($part, $eqPos + 1);

            # RFC 5802 section 5: an unknown mandatory extension (m=) must cause authentication to fail.
            if ($attr === 'm') {
                throw new SaslEncodingException('Received an unsupported mandatory SCRAM extension (m=).');
            }

            $message->set($attr, $value);
        }

        return $message;
    }

    /**
     * Strips the GS2 header from a client-first-message, recording it (and any authzid) on the message.
     *
     * Returns the data with the header removed, or unchanged when no GS2 header is present.
     */
    private function stripGs2Header(
        string $data,
        Message $message,
    ): string {
        if (preg_match(self::MATCH_GS2_HEADER, $data, $matches) !== 1) {
            return $data;
        }

        # Preserve the exact gs2-header bytes (including any authzid) for the channel-binding value.
        $authzidAttr = $matches[2];
        $message->set(
            self::GS2_HEADER,
            $matches[1] . ',' . $authzidAttr . ',',
        );
        if ($authzidAttr !== '') {
            $authzid = substr(
                $authzidAttr,
                2,
            );
            $message->set(
                SaslContext::AUTHZID,
                $authzid,
            );
        }

        return $matches[3];
    }
}
