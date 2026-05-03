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
use FreeDSx\Sasl\Challenge\ScramChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use FreeDSx\Sasl\SecurityStrength;

/**
 * Covers all SCRAM variants (RFC 5802 / RFC 7677). The variant is selected by passing one of the
 * SCRAM_* cases of MechanismName, e.g. `new ScramMechanism(MechanismName::SCRAM_SHA256)`.
 *
 * SCRAM does not define a post-authentication security layer; TLS is expected to provide
 * confidentiality and integrity instead.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ScramMechanism implements MechanismInterface
{
    private readonly HashAlgorithm $hashAlgorithm;

    /**
     * @throws SaslException if the provided MechanismName is not a SCRAM variant.
     */
    public function __construct(private readonly MechanismName $mechanism)
    {
        $hashAlgorithm = $mechanism->hashAlgorithm();
        if ($hashAlgorithm === null) {
            throw new SaslException(sprintf(
                'The mechanism "%s" is not a SCRAM variant.',
                $mechanism->value,
            ));
        }
        $this->hashAlgorithm = $hashAlgorithm;
    }

    public function getName(): MechanismName
    {
        return $this->mechanism;
    }

    public function challenge(bool $serverMode = false): ChallengeInterface
    {
        return new ScramChallenge(
            $serverMode,
            $this->hashAlgorithm,
            $this->mechanism->isChannelBinding(),
        );
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

    /**
     * SCRAM does not provide a post-authentication security layer.
     *
     * @throws SaslException
     */
    public function securityLayer(): SecurityLayerInterface
    {
        throw new SaslException(sprintf(
            'The %s mechanism does not provide a security layer.',
            $this->mechanism->value,
        ));
    }

    public function __toString(): string
    {
        return $this->mechanism->value;
    }
}
