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

/**
 * Given an array of mechanism names, choose the best one available.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MechanismSelector
{
    /**
     * @param MechanismInterface[] $mechanisms
     */
    public function __construct(private readonly array $mechanisms)
    {
    }

    /**
     * @param MechanismName[] $choices
     * @param array<string, mixed> $options
     *
     * @throws SaslException
     */
    public function select(
        array $choices = [],
        array $options = [],
    ): MechanismInterface {
        $available = $this->getAvailableMechsFromChoices($choices, $options);

        return $this->selectMech($available);
    }

    /**
     * From RFC 4422:
     *
     *   Mechanism negotiation is protocol specific.
     *
     *   Commonly, a protocol will specify that the server advertises
     *   supported and available mechanisms to the client via some facility
     *   provided by the protocol, and the client will then select the "best"
     *   mechanism from this list that it supports and finds suitable.
     *
     * So basically we are on our own in determining the best available mechanism from a list. This really seems like
     * something that should have been included in the RFC. There is SSF, but that was never formalized into an RFC and
     * some vendors have different ways of calculating it, making it somewhat less meaningful.
     *
     * @param MechanismInterface[] $available
     *
     * @throws SaslException
     */
    private function selectMech(array $available): MechanismInterface
    {
        # We sort the mechanisms by:
        #  1. Key size first.
        #  2. Privacy / encryption support.
        #  3. Integrity / signing support.
        #  4. Authentication support (anonymous should be at the bottom...)
        #  5. Authentication that is not plain text.
        usort(
            $available,
            static function (MechanismInterface $a, MechanismInterface $b): int {
                $sa = $a->securityStrength();
                $sb = $b->securityStrength();

                # We need to invert the boolean checks, expect for plain text (logic is already inverted).
                return (int) !$sa->supportsPrivacy() <=> (int) !$sb->supportsPrivacy()
                    ?: (int) !$sa->supportsIntegrity() <=> (int) !$sb->supportsIntegrity()
                    ?: $sa->maxKeySize() <=> $sb->maxKeySize()
                    ?: (int) !$sa->supportsAuth() <=> (int) !$sb->supportsAuth()
                    ?: (int) $sa->isPlainTextAuth() <=> (int) $sb->isPlainTextAuth();
            },
        );
        $first = array_shift($available);

        if (!$first instanceof MechanismInterface) {
            throw new SaslException('No supported SASL mechanisms could be found.');
        }

        return $first;
    }

    /**
     * @param MechanismName[] $choices
     * @param array<string, mixed> $options
     *
     * @return MechanismInterface[]
     *
     * @throws SaslException
     */
    private function getAvailableMechsFromChoices(
        array $choices,
        array $options,
    ): array {
        $available = $this->filterFromChoices($choices);
        if (count($available) === 0) {
            $this->throwException($choices);
        }

        $available = $this->filterOptions($available, $options);
        if (count($available) === 0) {
            $this->throwException($choices);
        }

        return $available;
    }

    /**
     * @param MechanismName[] $choices
     *
     * @return MechanismInterface[]
     */
    private function filterFromChoices(array $choices): array
    {
        if (count($choices) === 0) {
            return $this->mechanisms;
        }
        $filtered = [];

        foreach ($this->mechanisms as $mech) {
            if (in_array($mech->getName(), $choices, true)) {
                $filtered[] = $mech;
            }
        }

        return $filtered;
    }

    /**
     * @param MechanismInterface[] $available
     * @param array<string, mixed> $options
     *
     * @return MechanismInterface[]
     */
    private function filterOptions(
        array $available,
        array $options,
    ): array {
        $useIntegrity = (bool) ($options['use_integrity'] ?? false);
        $usePrivacy = (bool) ($options['use_privacy'] ?? false);

        # Don't need to worry whether it supports integrity or privacy...
        if (!$useIntegrity && !$usePrivacy) {
            return $available;
        }
        $supportsInt = [];
        $supportsPriv = [];

        # Filter to those only those supporting integrity...
        if ($useIntegrity) {
            $supportsInt = array_filter(
                $available,
                static fn (MechanismInterface $mech): bool => $mech->securityStrength()->supportsIntegrity(),
            );
        }
        # Filter to those only supporting privacy...
        if ($usePrivacy) {
            $supportsPriv = array_filter(
                $available,
                static fn (MechanismInterface $mech): bool => $mech->securityStrength()->supportsPrivacy(),
            );
        }

        return array_unique(array_merge($supportsInt, $supportsPriv), SORT_REGULAR);
    }

    /**
     * @param MechanismName[] $choices
     *
     * @throws SaslException
     */
    private function throwException(array $choices = []): void
    {
        $names = array_map(static fn (MechanismName $name): string => $name->value, $choices);

        throw new SaslException(sprintf(
            'No supported SASL mechanisms could be found from the provided choices: %s',
            implode(', ', $names),
        ));
    }
}
