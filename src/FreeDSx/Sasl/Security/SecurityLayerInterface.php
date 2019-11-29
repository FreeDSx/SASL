<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl\Security;

use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\SaslContext;

/**
 * The security layer interface. Security layers are responsible for any integrity / confidentiality provided by the
 * specific mechanisms.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SecurityLayerInterface
{
    /**
     * Wraps / Installs the security layer for a specific SASL context over a data stream.
     *
     * @throws SaslException
     */
    public function wrap(string $data, SaslContext $context): string;

    /**
     * Unwraps / uninstalls the security layer for a specific SASL context from a data stream.
     *
     * @throws SaslException
     */
    public function unwrap(string $data, SaslContext $context): string;
}
