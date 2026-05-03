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

use FreeDSx\Sasl\Challenge\AnonymousChallenge;
use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use FreeDSx\Sasl\SecurityStrength;

/**
 * The ANONYMOUS mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AnonymousMechanism implements MechanismInterface
{
    public function getName(): MechanismName
    {
        return MechanismName::ANONYMOUS;
    }

    public function challenge(bool $serverMode = false): ChallengeInterface
    {
        return new AnonymousChallenge($serverMode);
    }

    public function securityStrength(): SecurityStrength
    {
        return new SecurityStrength(
            supportsIntegrity: false,
            supportsPrivacy: false,
            supportsAuth: false,
            isPlainTextAuth: false,
            maxKeySize: 0,
        );
    }

    public function securityLayer(): SecurityLayerInterface
    {
        throw new SaslException('The ANONYMOUS mechanism does not support a security layer.');
    }
}
