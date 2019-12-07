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
use FreeDSx\Sasl\Challenge\PlainChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Security\SecurityLayerInterface;

/**
 * The PLAIN mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PlainMechanism implements MechanismInterface
{
    public const NAME = 'PLAIN';

    /**
     * {@inheritDoc}
     */
    public function getName(): string
    {
        return self::NAME;
    }

    /**
     * {@inheritDoc}
     */
    public function supportsIntegrity(): bool
    {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function supportsPrivacy(): bool
    {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function challenge(): ChallengeInterface
    {
        return new PlainChallenge();
    }

    /**
     * {@inheritDoc}
     */
    public function securityLayer(): SecurityLayerInterface
    {
       throw new SaslException('The PLAIN mechanism does not support a security layer.');
    }
}
