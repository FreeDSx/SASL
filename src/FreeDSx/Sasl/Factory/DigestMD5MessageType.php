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

namespace FreeDSx\Sasl\Factory;

/**
 * Message types produced by the DIGEST-MD5 message factory.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum DigestMD5MessageType: int
{
    case CLIENT_RESPONSE = 1;
    case SERVER_CHALLENGE = 2;
    case SERVER_RESPONSE = 3;
}
