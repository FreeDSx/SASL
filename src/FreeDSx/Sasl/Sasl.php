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
use FreeDSx\Sasl\Mechanism\AnonymousMechanism;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\MechanismInterface;
use FreeDSx\Sasl\Mechanism\PlainMechanism;

/**
 * The main SASL class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Sasl
{
    /**
     * @var MechanismInterface[]
     */
    protected $mechanisms = [];

    protected $options = [
        'supported' => []
    ];

    public function __construct(array $options = [])
    {
        $this->options = $options + $this->options;
        $this->initMechs();
    }

    /**
     * Get a mechanism object by its name.
     */
    public function get(string $mechanism): MechanismInterface
    {
        $mech = $this->mechanisms[$mechanism] ?? null;

        if ($mech === null) {
            throw new SaslException('The mechanism "%s" is not supported.');
        }

        return $mech;
    }

    /**
     * Whether or not the mechanism is supported.
     */
    public function supports(string $mechanism): bool
    {
        return isset($this->mechanisms()[$mechanism]);
    }

    /**
     * Add a mechanism object.
     *
     * @return Sasl
     */
    public function add(MechanismInterface $mechanism): self
    {
        $this->mechanisms[$mechanism->getName()] = $mechanism;

        return $this;
    }

    /**
     * Remove a mechanism by its name.
     *
     * @return Sasl
     */
    public function remove(string $mechanism): self
    {
        if (isset($this->mechanisms[$mechanism])) {
            unset($this->mechanisms[$mechanism]);
        }

        return $this;
    }

    /**
     * Given an array of mechanism names, and optional options, select the best supported mechanism available.
     *
     * @param string[] $choices array of mechanisms by their name
     * @param array $options array of options (ie. ['use_integrity' => true])
     * @return MechanismInterface the mechanism selected.
     * @throws SaslException if no supported mechanism could be found.
     */
    public function select(array $choices = [], array $options = []): MechanismInterface
    {
        $selector = new MechanismSelector($this->mechanisms());

        return $selector->select($choices, $options);
    }

    /**
     * @return MechanismInterface[]
     */
    public function mechanisms(): array
    {
        return $this->mechanisms;
    }

    protected function initMechs(): void
    {
        $this->mechanisms = [
            DigestMD5Mechanism::NAME => new DigestMD5Mechanism(),
            CramMD5Mechanism::NAME => new CramMD5Mechanism(),
            PlainMechanism::NAME => new PlainMechanism(),
            AnonymousMechanism::NAME => new AnonymousMechanism(),
        ];

        if (is_array($this->options['supported']) && !empty($this->options['supported'])) {
            foreach (array_keys($this->mechanisms) as $mechName) {
                if (!in_array($mechName, $this->options['supported'], true)) {
                    unset($this->mechanisms[$mechName]);
                }
            }
        }
    }
}
