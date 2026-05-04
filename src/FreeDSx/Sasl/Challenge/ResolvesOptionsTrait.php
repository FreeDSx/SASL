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

trait ResolvesOptionsTrait
{
    /**
     * @template T of ChallengeOptionsInterface
     *
     * @param class-string<T> $expectedClass
     *
     * @return T
     *
     * @throws SaslException
     */
    private function resolveOptions(
        ?ChallengeOptionsInterface $options,
        string $expectedClass,
    ): ChallengeOptionsInterface {
        if ($options !== null && !$options instanceof $expectedClass) {
            throw new SaslException(sprintf(
                'Expected %s, got %s.',
                $expectedClass,
                $options::class,
            ));
        }

        return $options;
    }
}
