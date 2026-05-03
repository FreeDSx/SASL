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
