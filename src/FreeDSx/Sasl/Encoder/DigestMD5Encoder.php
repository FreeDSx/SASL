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
use function dechex, explode, implode, preg_match, sprintf, str_pad, strlen, substr;

/**
 * Responsible for encoding / decoding DIGEST-MD5 messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DigestMD5Encoder implements EncoderInterface
{
    protected const MATCH_KEY = '/(([a-zA-Z-]+)=)/';

    protected const MATCH_QD_STR_VAL = '/("((.*?)(?<!\\\))")/';

    protected const MATCH_DIGITS = '/([0-9]+)/';

    protected const MATCH_ALPHA_NUMERIC = '/([A-Za-z0-9-]+)/';

    protected const MATCH_LHEX = '/([0-9a-fA-F]{1,})/';

    protected const ONCE_ONLY = [
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

    /**
     * @var string
     */
    protected $binary;

    /**
     * @var int
     */
    protected $pos = 0;

    /**
     * @var int
     */
    protected $length = 0;

    /**
     * Tracks the number of times a specific option is encountered during decoding.
     */
    protected $occurrences = [];

    /**
     * {@inheritDoc}
     */
    public function decode(string $data, SaslContext $context): Message
    {
        return $this->parse($data, !$context->isServerMode());
    }

    /**
     * {@inheritDoc}
     */
    public function encode(Message $message, SaslContext $context): string
    {
        $response = '';

        foreach ($message->toArray() as $key => $value) {
            if ($response !== '') {
                $response .= ',';
            }
            $response .= $key . '=' . $this->encodeOptValue(
                $key,
                $value,
                $context->isServerMode()
            );
        }

        return $response;
    }

    protected function startParsing(string $binary): void
    {
        $this->binary = $binary;
        $this->pos = 0;
        $this->length = strlen($binary);
        $this->occurrences = [];
    }

    protected function endParsing(): void
    {
        $this->binary = '';
        $this->pos = 0;
        $this->length = 0;
        $this->occurrences = [];
    }

    /**
     * @throws SaslEncodingException
     */
    protected function parse(string $digest, bool $isServerMode): Message
    {
        $this->startParsing($digest);

        $message = new Message();
        while ($this->pos < $this->length) {
            $keyMatches = null;
            if (!preg_match(self::MATCH_KEY, substr($this->binary, $this->pos), $keyMatches)) {
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
     * @return mixed
     * @throws SaslEncodingException
     */
    protected function parseOptValue(string $opt, bool $isServerMode)
    {
        $value = null;

        switch ($opt) {
            case 'realm':
            case 'nonce':
            case 'username':
            case 'cnonce':
            case 'authzid':
            case 'digest-uri':
                $value = $this->parseQuotedValue();
                break;
            case 'qop':
            case 'cipher':
                if ($isServerMode) {
                    $value = $this->parseQuotedCommaList();
                } else {
                    $value = $this->parseRegex(self::MATCH_ALPHA_NUMERIC, 'The value is malformed.');
                }
                break;
            case 'stale':
                $value = $this->parseExact('true');
                break;
            case 'maxbuf':
                $value = $this->parseRegex(self::MATCH_DIGITS, 'Expected a series of digits for a key value.');
                break;
            case 'algorithm':
                $value = $this->parseExact('md5-sess');
                break;
            case 'charset':
                $value = $this->parseExact('utf-8');
                break;
            case 'nc':
                $value = $this->parseLHexValue(8);
                break;
            case 'response':
            case 'rspauth':
                $value = $this->parseLHexValue(32);
                break;
            default:
                throw new SaslEncodingException(sprintf(
                    'Digest option %s is not supported.',
                    $opt
                ));
                break;
        }

        if (isset($this->binary[$this->pos]) && $this->binary[$this->pos] !== ',') {
            throw new SaslEncodingException(sprintf(
                'Expected a comma following digest value for %s.',
                $opt
            ));
        }
        if (isset($this->binary[$this->pos]) && $this->binary[$this->pos] === ',') {
            $this->pos++;
        }

        if (isset($this->occurrences[$opt]) && in_array($opt, self::ONCE_ONLY, true)) {
            throw new SaslEncodingException(sprintf('The option "%s" may occur only once.', $opt));
        } elseif (isset($this->occurrences[$opt])) {
            $this->occurrences[$opt]++;
        } else {
            $this->occurrences[$opt] = 1;
        }

        return $value;
    }

    /**
     * @return mixed
     * @throws SaslEncodingException
     */
    protected function encodeOptValue(string $name, $value, bool $isServerMode)
    {
        $encoded = null;

        switch ($name) {
            case 'realm':
            case 'nonce':
            case 'username':
            case 'cnonce':
            case 'authzid':
            case 'digest-uri':
                $encoded = '"' . str_replace(['\\', '"'], ['\\\\', '\"'], $value) . '"';
                break;
            case 'qop':
            case 'cipher':
                if ($isServerMode) {
                    $encoded = '"' . implode(',', (array) $value) . '"';
                } else {
                    $encoded = (string) $value;
                }
                break;
            case 'stale':
                $encoded = 'true';
                break;
            case 'maxbuf':
            case 'algorithm':
            case 'charset':
                $encoded = (string) $value;
                break;
            case 'nc':
                $encoded = str_pad(dechex($value), 8, '0', STR_PAD_LEFT);
                break;
            case 'response':
            case 'rspauth':
                $encoded = $this->encodeLHexValue($value, 32);
                break;
            default:
                throw new SaslEncodingException(sprintf(
                    'Digest option %s is not supported.',
                    $name
                ));
                break;
        }

        return $encoded;
    }

    /**
     * @throws SaslEncodingException
     */
    protected function parseExact(string $expected): string
    {
        $length = strlen($expected);
        if (substr($this->binary, $this->pos, $length) !== $expected) {
            throw new SaslEncodingException(sprintf(
                'Expected the directive value to be "%s", but it is not.',
                $expected
            ));
        }
        $this->pos += $length;

        return $expected;
    }

    /**
     * @throws SaslEncodingException
     */
    protected function parseQuotedValue(): string
    {
        if (!preg_match(self::MATCH_QD_STR_VAL, substr($this->binary, $this->pos), $matches)) {
            throw new SaslEncodingException('The value is malformed. Expected a qdstr-val.');
        }
        $this->pos += strlen($matches[1]);

        return stripslashes($matches[2]);
    }

    /**
     * @throws SaslEncodingException
     */
    protected function parseQuotedCommaList(): array
    {
        $value = $this->parseQuotedValue();

        return explode(',', $value);
    }

    /**
     * @throws SaslEncodingException
     */
    protected function parseLHexValue(int $length): string
    {
        if (!preg_match(self::MATCH_LHEX, substr($this->binary, $this->pos), $matches)) {
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
    protected function parseRegex(string $regex, string $errorMessage)
    {
        if (!preg_match($regex, substr($this->binary, $this->pos), $matches)) {
            throw new SaslEncodingException($errorMessage);
        }
        $this->pos += strlen($matches[1]);

        return $matches[1];
    }

    /**
     * @throws SaslEncodingException
     */
    protected function encodeLHexValue(string $data, int $length): string
    {
        if (strlen($data) !== $length) {
            throw new SaslEncodingException(sprintf('Expected the encoded hex value to be %s characters long.', $length));
        }

        return $data;
    }
}
