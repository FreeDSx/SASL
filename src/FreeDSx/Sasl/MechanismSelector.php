<?php

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

/**
 * Given an array of mechanism names, choose the best one available.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MechanismSelector
{
    /**
     * @var MechanismInterface[]
     */
    protected $mechanisms;

    /**
     * @param MechanismInterface[] $mechanisms
     */
    public function __construct(array $mechanisms)
    {
        $this->mechanisms = $mechanisms;
    }

    /**
     * @throws SaslException
     */
    public function select(array $choices = [], array $options = []): MechanismInterface
    {
        $mechs = $this->getAvailableMechsFromChoices($choices, $options);

        return $this->selectMech($mechs);
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
     * @return MechanismInterface
     * @throws SaslException
     */
    protected function selectMech(array $available): MechanismInterface
    {
        # We sort the mechanisms by:
        #  1. Key size first.
        #  2. Privacy / encryption support.
        #  3. Integrity / signing support.
        #  4. Authentication support (anonymous should be at the bottom...)
        #  5. Authentication that is not plain text.
        usort($available, function (MechanismInterface $mechA, MechanismInterface $mechB) {
            $strengthA = $mechA->securityStrength();
            $strengthB = $mechB->securityStrength();

            # We need to invert the boolean checks, expect for plain text (logic is already inverted).
            return (int)!$strengthA->supportsPrivacy() <=> (int)!$strengthB->supportsPrivacy()
                ?: (int)!$strengthA->supportsIntegrity() <=> (int)!$strengthB->supportsIntegrity()
                ?: (int)$strengthA->maxKeySize() <=> (int)$strengthB->maxKeySize()
                ?: (int)!$strengthA->supportsAuth() <=> (int)!$strengthB->supportsAuth()
                ?: (int)$strengthA->isPlainTextAuth() <=> (int)$strengthB->isPlainTextAuth();
        });
        $first = array_shift($available);

        if (!$first instanceof MechanismInterface) {
            throw new SaslException('No supported SASL mechanisms could be found.');
        }

        return $first;
    }

    /**
     * @param string[] $choices
     * @param array $options
     * @return MechanismInterface[]
     * @throws SaslException
     */
    protected function getAvailableMechsFromChoices(array $choices, array $options): array
    {
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
     * @param string[] $choices
     * @return MechanismInterface[]
     */
    protected function filterFromChoices(array $choices): array
    {
        if (count($choices) === 0) {
            return $this->mechanisms;
        }
        $filtered = [];

        foreach ($this->mechanisms as $choice) {
            if (in_array($choice->getName(), $choices, true)) {
                $filtered[] = $choice;
            }
        }

        return $filtered;
    }

    /**
     * @param MechanismInterface[] $available
     * @param array $options
     * @return MechanismInterface[]
     */
    protected function filterOptions(array $available, array $options): array
    {
        $useIntegrity = $options['use_integrity'] ?? false;
        $usePrivacy = $options['use_privacy'] ?? false;

        # Don't need to worry whether it supports integrity or privacy...
        if ($usePrivacy === false && $useIntegrity === false) {
            return $available;
        }
        $supportsInt = [];
        $supportsPriv = [];

        # Filter to those only those supporting integrity...
        if ($useIntegrity === true) {
            $supportsInt = array_filter($available, function (MechanismInterface $mech) use ($useIntegrity) {
                return $mech->securityStrength()->supportsIntegrity() === $useIntegrity;
            });
        }
        # Filter to those only supporting privacy...
        if ($usePrivacy === true) {
            $supportsPriv = array_filter($available, function (MechanismInterface $mech) use ($usePrivacy) {
                return $mech->securityStrength()->supportsPrivacy() === $usePrivacy;
            });
        }

        return array_unique(array_merge($supportsInt, $supportsPriv), SORT_REGULAR);
    }

    /**
     * @throws SaslException
     */
    protected function throwException(array $choices = []): void
    {
        throw new SaslException(sprintf(
            'No supported SASL mechanisms could be found from the provided choices: %s',
            implode($choices, ', ')
        ));
    }
}
