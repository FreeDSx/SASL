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
final readonly class CramMD5Mechanism implements MechanismInterface
{
    public function getName(): MechanismName
    {
        return MechanismName::CRAM_MD5;
    }

    public function challenge(bool $serverMode = false): ChallengeInterface
    {
        return new CramMD5Challenge($serverMode);
    }

    public function securityStrength(): SecurityStrength
    {
        return new SecurityStrength(
            supportsIntegrity: false,
            supportsPrivacy: false,
            supportsAuth: true,
            isPlainTextAuth: false,
            maxKeySize: 0,
        );
    }

    public function securityLayer(): SecurityLayerInterface
    {
        throw new SaslException('CRAM-MD5 does not support a security layer.');
    }
}
