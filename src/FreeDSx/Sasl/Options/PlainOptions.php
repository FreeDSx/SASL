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
 * Options for the PLAIN challenge.
 *
 * Client mode: set username and password.
 * Server mode: set the validate closure.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PlainOptions implements ChallengeOptionsInterface
{
    private ?string $username = null;

    private ?string $password = null;

    private ?string $authzId = null;

    /**
     * @var (Closure(?string $authzId, string $authcId, string $password): bool)|null
     */
    private ?Closure $validate = null;

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(string $username): self
    {
        $this->username = $username;

        return $this;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(string $password): self
    {
        $this->password = $password;

        return $this;
    }

    public function getAuthzId(): ?string
    {
        return $this->authzId;
    }

    /**
     * The identity to act as, for a proxy request; leave it unset to authorize as the authenticating identity.
     */
    public function setAuthzId(string $authzId): self
    {
        $this->authzId = $authzId;

        return $this;
    }

    /**
     * @return (Closure(?string $authzId, string $authcId, string $password): bool)|null
     */
    public function getValidate(): ?Closure
    {
        return $this->validate;
    }

    /**
     * @param Closure(?string $authzId, string $authcId, string $password): bool $validate
     */
    public function setValidate(Closure $validate): self
    {
        $this->validate = $validate;

        return $this;
    }
}
