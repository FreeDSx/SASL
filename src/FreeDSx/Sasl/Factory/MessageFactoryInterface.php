<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl\Factory;

use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Message;

/**
 * Used to instantiate messages of a specific type for a mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MessageFactoryInterface
{
    /**
     * Create a message object of a specific type for a given mechanism.
     *
     * @param int $type
     * @param array $options
     * @param Message|null $received
     * @return Message
     * @throws SaslException
     */
    public function create(int $type, array $options = [], ?Message $received = null): Message;
}
