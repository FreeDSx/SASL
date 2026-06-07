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
use FreeDSx\Sasl\Mechanism\ExternalMechanism;
use FreeDSx\Sasl\Mechanism\MechanismInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use FreeDSx\Sasl\Mechanism\ScramMechanism;
use FreeDSx\Sasl\Options\SaslOptions;
use FreeDSx\Sasl\Options\SelectOptions;

/**
 * The main SASL class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Sasl implements SaslInterface
{
    /**
     * @var array<string, MechanismInterface> keyed by MechanismName->value
     */
    private array $mechanisms = [];

    public function __construct(private readonly SaslOptions $options = new SaslOptions())
    {
        $this->initMechs();
    }

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

    public function supports(MechanismName $mechanism): bool
    {
        return isset($this->mechanisms[$mechanism->value]);
    }

    public function add(MechanismInterface $mechanism): static
    {
        $this->mechanisms[$mechanism->getName()->value] = $mechanism;

        return $this;
    }

    public function remove(MechanismName $mechanism): static
    {
        unset($this->mechanisms[$mechanism->value]);

        return $this;
    }

    public function select(
        array $choices = [],
        ?SelectOptions $options = null,
    ): MechanismInterface {
        return (new MechanismSelector($this->mechanisms))
            ->select($choices, $options);
    }

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
            MechanismName::EXTERNAL->value => new ExternalMechanism(),
        ];

        foreach (MechanismName::cases() as $case) {
            if ($case->isScram()) {
                $this->mechanisms[$case->value] = new ScramMechanism($case);
            }
        }

        if (count($this->options->getSupported()) === 0) {
            return;
        }

        $allowed = array_map(
            static fn (MechanismName $name): string => $name->value,
            $this->options->getSupported(),
        );
        foreach (array_keys($this->mechanisms) as $key) {
            if (!in_array($key, $allowed, true)) {
                unset($this->mechanisms[$key]);
            }
        }
    }
}
