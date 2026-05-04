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
 * Options for the DIGEST-MD5 challenge.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DigestMD5Options implements ChallengeOptionsInterface
{
    private bool $useIntegrity = false;

    private bool $usePrivacy = false;

    private string $service = 'ldap';

    private ?int $nonceSize = null;

    private ?string $username = null;

    private ?string $password = null;

    private ?string $host = null;

    private ?string $realm = null;

    private ?string $cnonce = null;

    private ?string $nonce = null;

    private ?string $cipher = null;

    private ?string $maxbuf = null;

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

    public function getService(): string
    {
        return $this->service;
    }

    public function setService(string $service): self
    {
        $this->service = $service;

        return $this;
    }

    public function getNonceSize(): ?int
    {
        return $this->nonceSize;
    }

    public function setNonceSize(int $nonceSize): self
    {
        $this->nonceSize = $nonceSize;

        return $this;
    }

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

    public function getHost(): ?string
    {
        return $this->host;
    }

    public function setHost(string $host): self
    {
        $this->host = $host;

        return $this;
    }

    public function getRealm(): ?string
    {
        return $this->realm;
    }

    public function setRealm(string $realm): self
    {
        $this->realm = $realm;

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

    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function setNonce(string $nonce): self
    {
        $this->nonce = $nonce;

        return $this;
    }

    public function getCipher(): ?string
    {
        return $this->cipher;
    }

    public function setCipher(string $cipher): self
    {
        $this->cipher = $cipher;

        return $this;
    }

    public function getMaxbuf(): ?string
    {
        return $this->maxbuf;
    }

    public function setMaxbuf(string $maxbuf): self
    {
        $this->maxbuf = $maxbuf;

        return $this;
    }
}
