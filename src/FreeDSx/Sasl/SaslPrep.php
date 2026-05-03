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

namespace FreeDSx\Sasl;

use FreeDSx\Sasl\Exception\SaslException;

/**
 * Implements the SASLprep string preparation profile (RFC 4013) over the stringprep framework (RFC 3454).
 *
 * Implements: B.1 map-to-nothing, C.1.2 space mapping, and prohibition checks C.2.1–C.2.2 (partial),
 * C.3–C.4 (BMP only), C.5 (via UTF-8 validity), C.6–C.9.
 *
 * Known gaps: NFKC normalization (requires ext-intl; affects non-ASCII inputs with multiple Unicode
 * representations), bidi check (RFC 3454 §6), supplementary-plane private use / non-character code
 * points (C.3/C.4), and non-C1 scattered control points (C.2.2). ASCII-only inputs are fully compliant.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslPrep
{
    /**
     * Maps named capture group names (from PROHIBITED_PATTERN) to their exception messages.
     * C.2.1 and C.2.2 share the 'control' group since they produce the same error.
     */
    private const PROHIBITED_ERRORS = [
        'control'   => self::ERR_CONTROL_CHAR,
        'private'   => self::ERR_PRIVATE_USE,
        'nonchar'   => self::ERR_NON_CHARACTER,
        'plaintext' => self::ERR_PLAIN_TEXT,
        'canonical' => self::ERR_CANONICAL,
        'display'   => self::ERR_DISPLAY_PROP,
        'tagging'   => self::ERR_TAGGING,
    ];

    /**
     * Single-pass pattern covering all RFC 4013 §2.3 prohibited ranges via named groups.
     * C.2.1 (ASCII control) and C.2.2 (C1 control) share the 'control' group.
     * C.5 (surrogates) is handled by mb_check_encoding rather than regex (PCRE2 disallows
     * surrogate ranges in Unicode character classes, and valid UTF-8 cannot encode them anyway).
     * See class docblock for remaining known gaps.
     */
    private const PROHIBITED_PATTERN =
        '/(?P<control>[\x00-\x1F\x7F\x{0080}-\x{009F}])'      // C.2.1 + C.2.2
        . '|(?P<private>[\x{E000}-\x{F8FF}])'                 // C.3
        . '|(?P<nonchar>[\x{FDD0}-\x{FDEF}\x{FFFE}\x{FFFF}])' // C.4
        . '|(?P<plaintext>[\x{FFF9}-\x{FFFD}])'               // C.6
        . '|(?P<canonical>[\x{2FF0}-\x{2FFB}])'               // C.7
        . '|(?P<display>[\x{0340}\x{0341}\x{200E}\x{200F}\x{202A}-\x{202E}\x{206A}-\x{206F}])' // C.8
        . '|(?P<tagging>[\x{E0001}\x{E0020}-\x{E007F}])/u';   // C.9

    /**
     * Characters from RFC 3454 Table B.1 that are commonly mapped to nothing.
     * Applied as the first step, before space mapping and normalization.
     */
    private const MAP_TO_NOTHING = [
        "\u{00AD}", // SOFT HYPHEN
        "\u{034F}", // COMBINING GRAPHEME JOINER
        "\u{1806}", // MONGOLIAN TODO SOFT HYPHEN
        "\u{180B}", // MONGOLIAN FREE VARIATION SELECTOR ONE
        "\u{180C}", // MONGOLIAN FREE VARIATION SELECTOR TWO
        "\u{180D}", // MONGOLIAN FREE VARIATION SELECTOR THREE
        "\u{200B}", // ZERO WIDTH SPACE
        "\u{200C}", // ZERO WIDTH NON-JOINER
        "\u{200D}", // ZERO WIDTH JOINER
        "\u{2060}", // WORD JOINER
        "\u{FE00}", // VARIATION SELECTOR-1
        "\u{FE01}", // VARIATION SELECTOR-2
        "\u{FE02}", // VARIATION SELECTOR-3
        "\u{FE03}", // VARIATION SELECTOR-4
        "\u{FE04}", // VARIATION SELECTOR-5
        "\u{FE05}", // VARIATION SELECTOR-6
        "\u{FE06}", // VARIATION SELECTOR-7
        "\u{FE07}", // VARIATION SELECTOR-8
        "\u{FE08}", // VARIATION SELECTOR-9
        "\u{FE09}", // VARIATION SELECTOR-10
        "\u{FE0A}", // VARIATION SELECTOR-11
        "\u{FE0B}", // VARIATION SELECTOR-12
        "\u{FE0C}", // VARIATION SELECTOR-13
        "\u{FE0D}", // VARIATION SELECTOR-14
        "\u{FE0E}", // VARIATION SELECTOR-15
        "\u{FE0F}", // VARIATION SELECTOR-16
        "\u{FEFF}", // ZERO WIDTH NO-BREAK SPACE (BOM)
    ];

    /**
     * Non-ASCII space characters from RFC 3454 Table C.1.2.
     * Each is mapped to a single ASCII space (U+0020).
     * Note: U+200B is intentionally absent — it is already deleted by MAP_TO_NOTHING (Table B.1).
     */
    private const MAP_TO_SPACE = [
        "\u{00A0}", // NO-BREAK SPACE
        "\u{1680}", // OGHAM SPACE MARK
        "\u{2000}", // EN QUAD
        "\u{2001}", // EM QUAD
        "\u{2002}", // EN SPACE
        "\u{2003}", // EM SPACE
        "\u{2004}", // THREE-PER-EM SPACE
        "\u{2005}", // FOUR-PER-EM SPACE
        "\u{2006}", // SIX-PER-EM SPACE
        "\u{2007}", // FIGURE SPACE
        "\u{2008}", // PUNCTUATION SPACE
        "\u{2009}", // THIN SPACE
        "\u{200A}", // HAIR SPACE
        "\u{2028}", // LINE SEPARATOR
        "\u{2029}", // PARAGRAPH SEPARATOR
        "\u{202F}", // NARROW NO-BREAK SPACE
        "\u{205F}", // MEDIUM MATHEMATICAL SPACE
        "\u{3000}", // IDEOGRAPHIC SPACE
    ];

    private const ERR_CONTROL_CHAR   = 'String contains a prohibited control character.';

    private const ERR_PRIVATE_USE    = 'String contains a prohibited private use character.';

    private const ERR_NON_CHARACTER  = 'String contains a prohibited non-character code point.';

    private const ERR_PLAIN_TEXT     = 'String contains a character inappropriate for plain text.';

    private const ERR_CANONICAL      = 'String contains a character inappropriate for canonical representation.';

    private const ERR_DISPLAY_PROP   = 'String contains a deprecated or display-property-altering character.';

    private const ERR_TAGGING        = 'String contains a prohibited tagging character.';

    /**
     * Prepares a string according to the SASLprep profile (RFC 4013).
     *
     * @throws SaslException if the string is not valid UTF-8 or contains a prohibited character.
     */
    public static function prepare(string $input): string
    {
        // Step 1: Map characters commonly mapped to nothing (RFC 3454 Table B.1).
        $input = str_replace(
            self::MAP_TO_NOTHING,
            '',
            $input
        );

        // Step 2: Map non-ASCII space characters to ASCII space (RFC 3454 Table C.1.2).
        $input = str_replace(
            self::MAP_TO_SPACE,
            ' ',
            $input
        );

        // @TODO Step 3: Unicode NFKC normalization (RFC 3454 §7).

        // Step 4: Check for prohibited output characters (RFC 4013 §2.3).
        self::checkProhibited($input);

        // @TODO Step 5: Bidirectional check (RFC 3454 §6).

        return $input;
    }

    /**
     * Checks the string for prohibited output characters per RFC 4013 §2.3.
     *
     * @throws SaslException
     */
    private static function checkProhibited(string $input): void
    {
        if (!mb_check_encoding($input, 'UTF-8')) {
            throw new SaslException('The string is not valid UTF-8.');
        }

        if (preg_match(self::PROHIBITED_PATTERN, $input, $matches) !== 1) {
            return;
        }

        foreach (self::PROHIBITED_ERRORS as $group => $message) {
            if (isset($matches[$group]) && $matches[$group] !== '') {
                throw new SaslException($message);
            }
        }
    }
}
