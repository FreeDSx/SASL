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

use FreeDSx\Sasl\Exception\SaslException;

/**
 * Holds SASL context specific data related to a particular mechanism challenge / response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslContext
{
    /**
     * Context data key for the authorization identity (authzid) a mechanism carried.
     */
    public const AUTHZID = 'authzid';

    private bool $isAuthenticated = false;

    private bool $isComplete = false;

    private bool $hasSecurityLayer = false;

    private bool $isServerMode = false;

    private ?string $response = null;

    /**
     * @param array<string, mixed> $data
     */
    public function __construct(private array $data = [])
    {
    }

    public function setIsComplete(bool $isComplete): self
    {
        $this->isComplete = $isComplete;

        return $this;
    }

    public function isComplete(): bool
    {
        return $this->isComplete;
    }

    public function setIsServerMode(bool $isServerMode): self
    {
        $this->isServerMode = $isServerMode;

        return $this;
    }

    public function isServerMode(): bool
    {
        return $this->isServerMode;
    }

    public function isAuthenticated(): bool
    {
        return $this->isAuthenticated;
    }

    public function setIsAuthenticated(bool $isAuthenticated): self
    {
        $this->isAuthenticated = $isAuthenticated;

        return $this;
    }

    public function hasSecurityLayer(): bool
    {
        return $this->hasSecurityLayer;
    }

    public function setHasSecurityLayer(bool $hasSecurityLayer): self
    {
        $this->hasSecurityLayer = $hasSecurityLayer;

        return $this;
    }

    public function getResponse(): ?string
    {
        return $this->response;
    }

    public function setResponse(?string $response): self
    {
        $this->response = $response;

        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * @param array<string, mixed> $data
     */
    public function setData(array $data): self
    {
        $this->data = $data;

        return $this;
    }

    public function has(string $key): bool
    {
        return isset($this->data[$key]);
    }

    public function get(string $key): mixed
    {
        return $this->data[$key] ?? null;
    }

    public function getString(string $key): string
    {
        $value = $this->data[$key] ?? null;

        return is_string($value)
            ? $value
            : '';
    }

    /**
     * @throws SaslException
     */
    public function getStringOrFail(string $key, string $errorMessage = ''): string
    {
        $value = $this->data[$key] ?? null;
        if (!is_string($value)) {
            throw new SaslException(
                $errorMessage !== '' ? $errorMessage : sprintf('The required key "%s" is missing.', $key),
            );
        }

        return $value;
    }

    public function getInt(string $key): ?int
    {
        $value = $this->data[$key] ?? null;
        return is_int($value) ? $value : null;
    }

    /**
     * The authorization identity (authzid) the client requested, when the mechanism carries one.
     */
    public function getAuthzId(): ?string
    {
        $value = $this->data[self::AUTHZID] ?? null;

        return is_string($value) ? $value : null;
    }

    public function set(
        string $key,
        mixed $value,
    ): self {
        $this->data[$key] = $value;

        return $this;
    }
}
