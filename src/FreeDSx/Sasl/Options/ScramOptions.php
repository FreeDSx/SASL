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
 * Options for the SCRAM challenge.
 *
 * Client-first: set username (required), and optionally cnonce and cbindType.
 * Client-final: set password (required), and optionally cbindData.
 * Server-first: optionally set nonce, salt, and iterations.
 * Server-final: set password (required for verification).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ScramOptions implements ChallengeOptionsInterface
{
    private ?string $username = null;

    private ?string $cnonce = null;

    private ?string $cbindType = null;

    private ?string $password = null;

    private ?string $cbindData = null;

    private ?string $nonce = null;

    private ?string $salt = null;

    private ?int $iterations = null;

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(string $username): self
    {
        $this->username = $username;

        return $this;
    }

    public function getCnonce(): ?string
    {
        return $this->cnonce;
    }

    public function setCnonce(string $cnonce): self
    {
        $this->cnonce = $cnonce;

        return $this;
    }

    public function getCbindType(): ?string
    {
        return $this->cbindType;
    }

    public function setCbindType(string $cbindType): self
    {
        $this->cbindType = $cbindType;

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

    public function getCbindData(): ?string
    {
        return $this->cbindData;
    }

    public function setCbindData(string $cbindData): self
    {
        $this->cbindData = $cbindData;

        return $this;
    }

    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function setNonce(string $nonce): self
    {
        $this->nonce = $nonce;

        return $this;
    }

    public function getSalt(): ?string
    {
        return $this->salt;
    }

    public function setSalt(string $salt): self
    {
        $this->salt = $salt;

        return $this;
    }

    public function getIterations(): ?int
    {
        return $this->iterations;
    }

    public function setIterations(int $iterations): self
    {
        $this->iterations = $iterations;

        return $this;
    }
}
