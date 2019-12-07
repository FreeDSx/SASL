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
use FreeDSx\Sasl\Challenge\CramMD5Challenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use FreeDSx\Sasl\SecurityStrength;

/**
 * The CRAM-MD5 mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class CramMD5Mechanism implements MechanismInterface
{
    public const NAME = 'CRAM-MD5';

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
    public function challenge(): ChallengeInterface
    {
        return new CramMD5Challenge();
    }

    /**
     * {@inheritDoc}
     */
    public function securityStrength(): SecurityStrength
    {
        return new SecurityStrength(
            false,
            false,
            true,
            false,
            0
        );
    }

    /**
     * {@inheritDoc}
     */
    public function securityLayer(): SecurityLayerInterface
    {
        throw new SaslException('CRAM-MD5 does not support a security layer.');
    }
}
