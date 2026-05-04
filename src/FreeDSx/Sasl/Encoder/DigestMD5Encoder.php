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
 * Responsible for encoding / decoding DIGEST-MD5 messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DigestMD5Encoder implements EncoderInterface
{
    private const MATCH_KEY = '/(([a-zA-Z-]+)=)/';

    private const MATCH_QD_STR_VAL = '/("((.*?)(?<!\\\))")/';

    private const MATCH_DIGITS = '/([0-9]+)/';

    private const MATCH_ALPHA_NUMERIC = '/([A-Za-z0-9-]+)/';

    private const MATCH_LHEX = '/([0-9a-fA-F]{1,})/';

    private const ONCE_ONLY = [
        'stale',
        'maxbuf',
        'charset',
        'algorithm',
        'nonce',
        'cnonce',
        'nc',
        'qop',
        'digest-uri',
        'response',
        'cipher',
    ];

    private string $binary = '';

    private int $pos = 0;

    private int $length = 0;

    /**
     * @var array<string, int>
     */
    private array $occurrences = [];

    public function decode(
        string $data,
        SaslContext $context,
    ): Message {
        return $this->parse($data, !$context->isServerMode());
    }

    public function encode(
        Message $message,
        SaslContext $context,
    ): string {
        $response = '';
        foreach (array_keys($message->toArray()) as $key) {
            if ($response !== '') {
                $response .= ',';
            }
            $response .= $key . '=' . $this->encodeOptValue(
                $key,
                $message,
                $context->isServerMode(),
            );
        }

        return $response;
    }

    private function startParsing(string $binary): void
    {
        $this->binary = $binary;
        $this->pos = 0;
        $this->length = strlen($binary);
        $this->occurrences = [];
    }

    private function endParsing(): void
    {
        $this->binary = '';
        $this->pos = 0;
        $this->length = 0;
        $this->occurrences = [];
    }

    /**
     * @throws SaslEncodingException
     */
    private function parse(
        string $digest,
        bool $isServerMode,
    ): Message {
        $this->startParsing($digest);

        $message = new Message();
        while ($this->pos < $this->length) {
            $keyMatches = null;
            if (preg_match(self::MATCH_KEY, substr($this->binary, $this->pos), $keyMatches) !== 1) {
                throw new SaslEncodingException('The digest is malformed. Expected a key, but none was found.');
            }
            $this->pos += strlen($keyMatches[1]);
            if (!isset($this->binary[$this->pos])) {
                throw new SaslEncodingException('Unexpected end of digest. Expected a value following a key.');
            }
            $message->set($keyMatches[2], $this->parseOptValue($keyMatches[2], $isServerMode));
        }
        $this->endParsing();

        return $message;
    }

    /**
     * @throws SaslEncodingException
     */
    private function parseOptValue(
        string $opt,
        bool $isServerMode,
    ): mixed {
        $value = match ($opt) {
            'realm', 'nonce', 'username', 'cnonce', 'authzid', 'digest-uri'
                => $this->parseQuotedValue(),
            'qop', 'cipher'
                => $isServerMode
                    ? $this->parseQuotedCommaList()
                    : $this->parseRegex(self::MATCH_ALPHA_NUMERIC, 'The value is malformed.'),
            'stale' => $this->parseExact('true'),
            'maxbuf' => $this->parseRegex(self::MATCH_DIGITS, 'Expected a series of digits for a key value.'),
            'algorithm' => $this->parseExact('md5-sess'),
            'charset' => $this->parseExact('utf-8'),
            'nc' => $this->parseLHexValue(8),
            'response', 'rspauth' => $this->parseLHexValue(32),
            default => throw new SaslEncodingException(sprintf(
                'Digest option %s is not supported.',
                $opt,
            )),
        };

        if (isset($this->binary[$this->pos]) && $this->binary[$this->pos] !== ',') {
            throw new SaslEncodingException(sprintf(
                'Expected a comma following digest value for %s.',
                $opt,
            ));
        }
        if (isset($this->binary[$this->pos]) && $this->binary[$this->pos] === ',') {
            $this->pos++;
        }

        if (isset($this->occurrences[$opt]) && in_array($opt, self::ONCE_ONLY, true)) {
            throw new SaslEncodingException(sprintf('The option "%s" may occur only once.', $opt));
        }
        $this->occurrences[$opt] = ($this->occurrences[$opt] ?? 0) + 1;

        return $value;
    }

    /**
     * @throws SaslEncodingException
     */
    private function encodeOptValue(
        string $name,
        Message $message,
        bool $isServerMode,
    ): string {
        return match ($name) {
            'realm', 'nonce', 'username', 'cnonce', 'authzid', 'digest-uri'
                => '"' . str_replace(['\\', '"'], ['\\\\', '\"'], $message->getString($name) ?? '') . '"',
            'qop', 'cipher'
                => $isServerMode
                    ? '"' . implode(',', $message->getStringArray($name) ?? []) . '"'
                    : ($message->getString($name) ?? ''),
            'stale' => 'true',
            'maxbuf', 'algorithm', 'charset' => $message->getString($name) ?? '',
            'nc' => str_pad(dechex($message->getInt($name) ?? 0), 8, '0', STR_PAD_LEFT),
            'response', 'rspauth' => $this->encodeLHexValue($message->getString($name) ?? '', 32),
            default => throw new SaslEncodingException(sprintf(
                'Digest option %s is not supported.',
                $name,
            )),
        };
    }

    /**
     * @throws SaslEncodingException
     */
    private function parseExact(string $expected): string
    {
        $length = strlen($expected);
        if (substr($this->binary, $this->pos, $length) !== $expected) {
            throw new SaslEncodingException(sprintf(
                'Expected the directive value to be "%s", but it is not.',
                $expected,
            ));
        }
        $this->pos += $length;

        return $expected;
    }

    /**
     * @throws SaslEncodingException
     */
    private function parseQuotedValue(): string
    {
        if (preg_match(self::MATCH_QD_STR_VAL, substr($this->binary, $this->pos), $matches) !== 1) {
            throw new SaslEncodingException('The value is malformed. Expected a qdstr-val.');
        }
        $this->pos += strlen($matches[1]);

        return stripslashes($matches[2]);
    }

    /**
     * @return string[]
     *
     * @throws SaslEncodingException
     */
    private function parseQuotedCommaList(): array
    {
        return explode(',', $this->parseQuotedValue());
    }

    /**
     * @throws SaslEncodingException
     */
    private function parseLHexValue(int $length): string
    {
        if (preg_match(self::MATCH_LHEX, substr($this->binary, $this->pos), $matches) !== 1) {
            throw new SaslEncodingException('Expected a hex value.');
        }
        if (strlen($matches[1]) !== $length) {
            throw new SaslEncodingException(sprintf('Expected the hex value to be %s characters long.', $length));
        }
        $this->pos += strlen($matches[1]);

        return $matches[1];
    }

    /**
     * @throws SaslEncodingException
     */
    private function parseRegex(
        string $regex,
        string $errorMessage,
    ): string {
        if (preg_match($regex, substr($this->binary, $this->pos), $matches) !== 1) {
            throw new SaslEncodingException($errorMessage);
        }
        $this->pos += strlen($matches[1]);

        return $matches[1];
    }

    /**
     * @throws SaslEncodingException
     */
    private function encodeLHexValue(
        string $data,
        int $length,
    ): string {
        if (strlen($data) !== $length) {
            throw new SaslEncodingException(sprintf('Expected the encoded hex value to be %s characters long.', $length));
        }

        return $data;
    }
}
