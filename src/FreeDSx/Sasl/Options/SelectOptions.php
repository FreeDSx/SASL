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

/**
 * Options controlling which mechanism is selected.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SelectOptions
{
    private bool $useIntegrity = false;

    private bool $usePrivacy = false;

    public function isUseIntegrity(): bool
    {
        return $this->useIntegrity;
    }

    public function setUseIntegrity(bool $useIntegrity): self
    {
        $this->useIntegrity = $useIntegrity;

        return $this;
    }

    public function isUsePrivacy(): bool
    {
        return $this->usePrivacy;
    }

    public function setUsePrivacy(bool $usePrivacy): self
    {
        $this->usePrivacy = $usePrivacy;

        return $this;
    }
}
