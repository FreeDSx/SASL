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

namespace FreeDSx\Sasl\Options;

use FreeDSx\Sasl\Mechanism\MechanismName;

/**
 * Top-level options for the Sasl class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslOptions
{
    /**
     * @param MechanismName[] $supported Limit available mechanisms to this set (empty = all supported).
     */
    public function __construct(private array $supported = [])
    {
    }

    /**
     * @return MechanismName[]
     */
    public function getSupported(): array
    {
        return $this->supported;
    }

    /**
     * @param MechanismName[] $supported
     */
    public function setSupported(array $supported): self
    {
        $this->supported = $supported;

        return $this;
    }
}
