<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl;

use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\SaslPrep;
use PHPUnit\Framework\TestCase;

class SaslPrepTest extends TestCase
{
    /**
     * @dataProvider mappingCases
     */
    public function testPrepare(string $input, string $expected, string $message): void
    {
        $this->assertSame(
            $expected,
            SaslPrep::prepare($input),
            $message
        );
    }

    /**
     * @dataProvider prohibitedCases
     */
    public function testPrepareThrowsOnProhibitedCharacter(string $input): void
    {
        $this->expectException(SaslException::class);

        SaslPrep::prepare($input);
    }

    public function mappingCases(): array
    {
        return [
            ['user', 'user', 'ASCII string is returned unchanged'],
            ['hello world', 'hello world', 'ASCII string with space is returned unchanged'],

            // RFC 3454 Table B.1 — map to nothing
            ["pass\u{00AD}word", 'password', 'soft hyphen (U+00AD) is removed'],
            ["pass\u{200B}word", 'password', 'zero width space (U+200B) is removed'],
            ["pass\u{FE0F}word", 'password', 'variation selector-16 (U+FE0F) is removed'],
            ["\u{FEFF}password", 'password', 'byte order mark (U+FEFF) is removed'],
            ["p\u{00AD}a\u{034F}s\u{2060}s", 'pass', 'multiple map-to-nothing characters are all removed'],

            // RFC 3454 Table C.1.2 — map to ASCII space
            ["hello\u{00A0}world", 'hello world', 'no-break space (U+00A0) is mapped to ASCII space'],
            ["hello\u{3000}world", 'hello world', 'ideographic space (U+3000) is mapped to ASCII space'],
            ["hello\u{2028}world", 'hello world', 'line separator (U+2028) is mapped to ASCII space'],
            ["hello\u{2000}world", 'hello world', 'en quad (U+2000) is mapped to ASCII space'],
        ];
    }

    public function prohibitedCases(): array
    {
        return [
            // C.2.1 — ASCII control characters
            'null byte (U+0000)'       => ["pass\x00word"],
            'unit separator (U+001F)'  => ["pass\x1Fword"],
            'delete character (U+007F)' => ["pass\x7Fword"],

            // C.2.2 — Non-ASCII control characters (C1 range)
            'first C1 control (U+0080)' => ["pass\u{0080}word"],
            'last C1 control (U+009F)'  => ["pass\u{009F}word"],

            // C.3 — Private use characters
            'first BMP private use (U+E000)' => ["pass\u{E000}word"],
            'last BMP private use (U+F8FF)'  => ["pass\u{F8FF}word"],

            // C.4 — Non-character code points
            'first non-character in FDD0-FDEF block (U+FDD0)' => ["pass\u{FDD0}word"],
            'non-character U+FFFE'                             => ["pass\u{FFFE}word"],
            'non-character U+FFFF'                             => ["pass\u{FFFF}word"],

            // C.6 — Inappropriate for plain text
            'interlinear annotation anchor (U+FFF9)' => ["pass\u{FFF9}word"],
            'replacement character (U+FFFD)'         => ["pass\u{FFFD}word"],

            // C.7 — Inappropriate for canonical representation
            'ideographic description character left-to-right (U+2FF0)' => ["pass\u{2FF0}word"],

            // C.8 — Change display properties or deprecated
            'left-to-right mark (U+200E)'    => ["pass\u{200E}word"],
            'right-to-left mark (U+200F)'    => ["pass\u{200F}word"],
            'left-to-right override (U+202D)' => ["pass\u{202D}word"],

            // C.9 — Tagging characters
            'tag space (U+E0020)' => ["pass\u{E0020}word"],
        ];
    }
}
