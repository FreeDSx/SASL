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

namespace FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\SaslContext;

/**
 * The challenge / response interface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChallengeInterface
{
    /**
     * Generate the next response to send in the challenge.
     *
     * @param string|null $received the last message received, or null if none
     * @param ?ChallengeOptionsInterface $options mechanism-specific options DTO
     *
     * @throws SaslException
     */
    public function challenge(
        ?string $received = null,
        ?ChallengeOptionsInterface $options = null,
    ): SaslContext;
}
