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

/**
 * Describes the "strength" of a particular mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SecurityStrength
{
    public function __construct(
        private readonly bool $supportsIntegrity,
        private readonly bool $supportsPrivacy,
        private readonly bool $supportsAuth,
        private readonly bool $isPlainTextAuth,
        private readonly int $maxKeySize,
    ) {
    }

    public function supportsIntegrity(): bool
    {
        return $this->supportsIntegrity;
    }

    public function supportsPrivacy(): bool
    {
        return $this->supportsPrivacy;
    }

    public function supportsAuth(): bool
    {
        return $this->supportsAuth;
    }

    public function isPlainTextAuth(): bool
    {
        return $this->isPlainTextAuth;
    }

    public function maxKeySize(): int
    {
        return $this->maxKeySize;
    }
}
