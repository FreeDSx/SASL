<?php

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
class SecurityStrength
{
    /**
     * @var bool
     */
    protected $supportsIntegrity;

    /**
     * @var bool
     */
    protected $supportsPrivacy;

    /**
     * @var bool
     */
    protected $supportsAuth;

    /**
     * @var bool
     */
    protected $isPlainTextAuth;

    /**
     * @var int
     */
    protected $maxKeySize;

    public function __construct(
        bool $supportsIntegrity,
        bool $supportsPrivacy,
        bool $supportsAuth,
        bool $isPlainTextAuth,
        int $maxKeySize
    ) {
        $this->supportsIntegrity = $supportsIntegrity;
        $this->supportsPrivacy = $supportsPrivacy;
        $this->supportsAuth = $supportsAuth;
        $this->isPlainTextAuth = $isPlainTextAuth;
        $this->maxKeySize = $maxKeySize;
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
