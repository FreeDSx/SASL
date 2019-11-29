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
 * Holds SASL context specific data related to a particular mechanism challenge / response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SaslContext
{
    /**
     * @var bool
     */
    protected $isAuthenticated = false;

    /**
     * @var bool
     */
    protected $isComplete = false;

    /**
     * @var bool
     */
    protected $hasSecurityLayer = false;

    /**
     * @var bool
     */
    protected $isServerMode = false;

    /**
     * @var array
     */
    protected $data = [];

    /**
     * @var string|null
     */
    protected $response;

    public function __construct(array $data = [])
    {
        $this->data = $data;
    }

    /**
     * @param bool $isComplete
     * @return $this
     */
    public function setIsComplete(bool $isComplete)
    {
        $this->isComplete = $isComplete;

        return $this;
    }

    /**
     * Whether or not the challenge sequence is complete.
     */
    public function isComplete(): bool
    {
        return $this->isComplete;
    }

    /**
     * @param bool $isServerMode
     * @return $this
     */
    public function setIsServerMode(bool $isServerMode)
    {
        $this->isServerMode = $isServerMode;

        return $this;
    }

    /**
     * Whether or not we are in the context of server mode for the exchange.
     */
    public function isServerMode(): bool
    {
        return $this->isServerMode;
    }

    /**
     * Whether or not the message exchange has resulted is being successfully authenticated.
     */
    public function isAuthenticated(): bool
    {
        return $this->isAuthenticated;
    }

    /**
     * Set whether or not the current context has authenticated.
     */
    public function setIsAuthenticated(bool $isAuthenticated)
    {
        $this->isAuthenticated = $isAuthenticated;

        return $this;
    }

    /**
     * Whether or not a security layer was negotiated as part of the message exchange.
     */
    public function hasSecurityLayer(): bool
    {
        return $this->hasSecurityLayer;
    }

    /**
     * Set whether or not the current context has negotiated a security layer.
     */
    public function setHasSecurityLayer(bool $hasSecurityLayer): self
    {
        $this->hasSecurityLayer = $hasSecurityLayer;

        return $this;
    }

    /**
     * The next response, if any, to send in the challenge.
     */
    public function getResponse(): ?string
    {
        return $this->response;
    }

    /**
     * @param string|null $response
     * @return $this
     */
    public function setResponse(?string $response)
    {
        $this->response = $response;

        return $this;
    }

    /**
     * Get any mechanism specific data that needs to be stored as part of the message exchange.
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * @param array $data
     * @return $this
     */
    public function setData(array $data)
    {
        $this->data = $data;

        return $this;
    }

    /**
     * Check if a SASL specific data piece exists.
     */
    public function has(string $key): bool
    {
        return isset($this->data[$key]);
    }

    /**
     * Get a SASL specific data piece. f
     *
     * @return mixed
     */
    public function get(string $key)
    {
        return $this->data[$key] ?? null;
    }

    /**
     * Set the value of a SASL specific data piece.
     */
    public function set(string $key, $value): self
    {
        $this->data[$key] = $value;

        return $this;
    }
}
