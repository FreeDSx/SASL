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
use FreeDSx\Sasl\Mechanism\AnonymousMechanism;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\MechanismInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use FreeDSx\Sasl\Mechanism\ScramMechanism;

/**
 * The main SASL class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Sasl
{
    /**
     * @var array<string, MechanismInterface> keyed by MechanismName->value
     */
    private array $mechanisms = [];

    /**
     * @var array{supported: MechanismName[]}
     */
    private array $options;

    /**
     * @param array{supported?: MechanismName[]} $options
     */
    public function __construct(array $options = [])
    {
        $this->options = $options + ['supported' => []];
        $this->initMechs();
    }

    /**
     * Get a mechanism object by its name.
     *
     * @throws SaslException
     */
    public function get(MechanismName $mechanism): MechanismInterface
    {
        $mech = $this->mechanisms[$mechanism->value] ?? null;
        if ($mech === null) {
            throw new SaslException(sprintf(
                'The mechanism "%s" is not supported.',
                $mechanism->value,
            ));
        }

        return $mech;
    }

    /**
     * Whether or not the mechanism is supported.
     */
    public function supports(MechanismName $mechanism): bool
    {
        return isset($this->mechanisms[$mechanism->value]);
    }

    /**
     * Add a mechanism object.
     */
    public function add(MechanismInterface $mechanism): self
    {
        $this->mechanisms[$mechanism->getName()->value] = $mechanism;

        return $this;
    }

    /**
     * Remove a mechanism by its name.
     */
    public function remove(MechanismName $mechanism): self
    {
        unset($this->mechanisms[$mechanism->value]);

        return $this;
    }

    /**
     * Given an array of mechanism names, and optional options, select the best supported mechanism available.
     *
     * @param MechanismName[] $choices array of mechanisms by their name
     * @param array<string, mixed> $options array of options (ie. ['use_integrity' => true])
     *
     * @throws SaslException
     */
    public function select(
        array $choices = [],
        array $options = [],
    ): MechanismInterface {
        return (new MechanismSelector($this->mechanisms))
            ->select($choices, $options);
    }

    /**
     * @return array<string, MechanismInterface>
     */
    public function mechanisms(): array
    {
        return $this->mechanisms;
    }

    private function initMechs(): void
    {
        $this->mechanisms = [
            MechanismName::DIGEST_MD5->value => new DigestMD5Mechanism(),
            MechanismName::CRAM_MD5->value => new CramMD5Mechanism(),
            MechanismName::PLAIN->value => new PlainMechanism(),
            MechanismName::ANONYMOUS->value => new AnonymousMechanism(),
        ];

        foreach (MechanismName::cases() as $case) {
            if ($case->isScram()) {
                $this->mechanisms[$case->value] = new ScramMechanism($case);
            }
        }

        if (count($this->options['supported']) === 0) {
            return;
        }

        $allowed = array_map(
            static fn (MechanismName $name): string => $name->value,
            $this->options['supported'],
        );
        foreach (array_keys($this->mechanisms) as $key) {
            if (!in_array($key, $allowed, true)) {
                unset($this->mechanisms[$key]);
            }
        }
    }
}
