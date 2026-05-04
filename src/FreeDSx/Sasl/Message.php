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

use ArrayIterator;
use Countable;
use FreeDSx\Sasl\Exception\SaslException;
use IteratorAggregate;
use Traversable;

/**
 * The message object encapsulates options / values for all mechanism messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
/**
 * @implements IteratorAggregate<string, mixed>
 */
final class Message implements Countable, IteratorAggregate
{
    /**
     * @param array<string, mixed> $data
     */
    public function __construct(private array $data = [])
    {
    }

    public function get(string $name): mixed
    {
        return $this->data[$name] ?? null;
    }

    public function getString(string $name): string
    {
        $value = $this->data[$name] ?? null;

        return is_string($value)
            ? $value
            : '';
    }

    /**
     * @throws SaslException
     */
    public function getStringOrFail(
        string $name,
        string $errorMessage = '',
    ): string {
        $value = $this->data[$name] ?? null;

        if (!is_string($value)) {
            throw new SaslException(
                $errorMessage !== ''
                    ? $errorMessage
                    : sprintf('The required field "%s" is missing.', $name),
            );
        }

        return $value;
    }

    public function getInt(string $name): ?int
    {
        $value = $this->data[$name] ?? null;

        return is_int($value)
            ? $value
            : null;
    }

    /**
     * Returns the value as int whether it is stored as int or as a numeric string.
     */
    public function getIntOrParse(string $name): ?int
    {
        $value = $this->data[$name] ?? null;
        if (is_int($value)) {
            return $value;
        }

        if (is_string($value)) {
            return (int) $value;
        }

        return null;
    }

    /**
     * @return mixed[]|null
     */
    public function getArray(string $name): ?array
    {
        $value = $this->data[$name] ?? null;

        return is_array($value)
            ? $value
            : null;
    }

    /**
     * @return string[]|null
     */
    public function getStringArray(string $name): ?array
    {
        $value = $this->data[$name] ?? null;
        if (!is_array($value)) {
            return null;
        }
        $strings = [];

        foreach ($value as $v) {
            if (is_string($v)) {
                $strings[] = $v;
            }
        }

        return $strings;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->data);
    }

    public function set(
        string $name,
        mixed $value,
    ): self {
        $this->data[$name] = $value;

        return $this;
    }

    public function count(): int
    {
        return count($this->data);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->data;
    }

    /**
     * @return Traversable<string, mixed>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->data);
    }
}
