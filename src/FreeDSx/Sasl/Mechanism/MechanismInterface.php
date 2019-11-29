<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl\Mechanism;

use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\Security\SecurityLayerInterface;

/**
 * Common methods mechanisms must implement.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MechanismInterface
{
    /**
     * Retrieve the registered name for this SASL mechanism.
     */
    public function getName(): string;

    /**
     * Whether or not this mechanism supports integrity.
     */
    public function supportsIntegrity(): bool;

    /**
     * Whether or not this mechanism supports privacy.
     */
    public function supportsPrivacy(): bool;

    /**
     * Get the challenge object for this mechanism.
     */
    public function challenge(): ChallengeInterface;

    /**
     * Get the security layer object for this mechanism.
     */
    public function security(): SecurityLayerInterface;
}
