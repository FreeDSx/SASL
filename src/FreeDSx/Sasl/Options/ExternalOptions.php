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

use Closure;

/**
 * Options for the EXTERNAL challenge.
 *
 * - Client mode: optionally set the authzId.
 * - Server mode: set the validate closure.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ExternalOptions implements ChallengeOptionsInterface
{
    private ?string $authzId = null;

    /**
     * @var (Closure(?string $authzId): bool)|null
     */
    private ?Closure $validate = null;

    public function getAuthzId(): ?string
    {
        return $this->authzId;
    }

    public function setAuthzId(?string $authzId): self
    {
        $this->authzId = $authzId;

        return $this;
    }

    /**
     * @return (Closure(?string $authzId): bool)|null
     */
    public function getValidate(): ?Closure
    {
        return $this->validate;
    }

    /**
     * @param Closure(?string $authzId): bool $validate
     */
    public function setValidate(Closure $validate): self
    {
        $this->validate = $validate;

        return $this;
    }
}
