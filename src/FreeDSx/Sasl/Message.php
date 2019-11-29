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

use Countable, IteratorAggregate;
use function array_key_exists, count;

/**
 * The message object encapsulates options / values for all mechanism messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Message implements Countable, IteratorAggregate
{
    protected $data = [];

    public function __construct(array $data = [])
    {
        $this->data = $data;
    }

    /**
     * @return mixed
     */
    public function get(string $name)
    {
        return $this->data[$name] ?? null;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->data);
    }

    /**
     * @param mixed $value
     * @return Message
     */
    public function set(string $name, $value): self
    {
        $this->data[$name] = $value;

        return $this;
    }

    public function count(): int
    {
        return count($this->data);
    }

    public function toArray(): array
    {
        return $this->data;
    }

    public function getIterator()
    {
        return new \ArrayIterator($this->data);
    }
}
