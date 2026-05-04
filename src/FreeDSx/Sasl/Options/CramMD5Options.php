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
 * Options for the CRAM-MD5 challenge.
 *
 * Client mode: set username and password.
 *
 * Server mode (initial): set challenge to override the auto-generated nonce.
 * Server mode (validation): set passwordCallback to verify the client digest.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class CramMD5Options implements ChallengeOptionsInterface
{
    private ?string $username = null;

    private ?string $password = null;

    private ?string $challenge = null;

    /**
     * @var (Closure(string $username, string $challenge): string)|null
     */
    private ?Closure $passwordCallback = null;

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

    public function getChallenge(): ?string
    {
        return $this->challenge;
    }

    public function setChallenge(string $challenge): self
    {
        $this->challenge = $challenge;

        return $this;
    }

    /**
     * @return (Closure(string $username, string $challenge): string)|null
     */
    public function getPasswordCallback(): ?Closure
    {
        return $this->passwordCallback;
    }

    /**
     * @param Closure(string $username, string $challenge): string $passwordCallback
     */
    public function setPasswordCallback(Closure $passwordCallback): self
    {
        $this->passwordCallback = $passwordCallback;

        return $this;
    }
}
