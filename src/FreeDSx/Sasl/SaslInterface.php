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
use FreeDSx\Sasl\Mechanism\MechanismInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\SelectOptions;

/**
 * The SASL interface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SaslInterface
{
    /**
     * Get a mechanism by its name.
     *
     * @throws SaslException
     */
    public function get(MechanismName $mechanism): MechanismInterface;

    /**
     * Whether the mechanism is supported.
     */
    public function supports(MechanismName $mechanism): bool;

    /**
     * Add a mechanism.
     */
    public function add(MechanismInterface $mechanism): static;

    /**
     * Remove a mechanism by name.
     */
    public function remove(MechanismName $mechanism): static;

    /**
     * Select the best available mechanism from the given choices.
     *
     * @param MechanismName[] $choices
     * @throws SaslException
     */
    public function select(
        array $choices = [],
        ?SelectOptions $options = null,
    ): MechanismInterface;

    /**
     * All registered mechanisms, keyed by MechanismName value.
     *
     * @return array<string, MechanismInterface>
     */
    public function mechanisms(): array;
}
