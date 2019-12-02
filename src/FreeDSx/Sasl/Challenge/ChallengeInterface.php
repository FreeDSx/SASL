<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\SaslContext;

/**
 * The challenge / response interface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChallengeInterface
{
    /**
     * Generate the next response to send in the challenge. It takes two optional parameters:
     *
     *  - The last message received. Null if no message has been received yet.
     *  - An array of options used for generating the next message.
     *
     * The SaslContext returned indicates various aspects of the state of the challenge, including the response.
     *
     * @throws SaslException
     */
    public function challenge(?string $received = null, array $options = []): SaslContext;
}
