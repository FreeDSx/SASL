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
use FreeDSx\Sasl\SecurityStrength;

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
     * Describes various security related aspects of the mechanism.
     */
    public function securityStrength(): SecurityStrength;

    /**
     * Get the challenge object for this mechanism.
     */
    public function challenge(): ChallengeInterface;

    /**
     * Get the security layer object for this mechanism.
     */
    public function securityLayer(): SecurityLayerInterface;
}
