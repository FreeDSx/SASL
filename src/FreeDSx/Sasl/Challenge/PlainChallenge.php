<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Encoder\PlainEncoder;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;

/**
 * The PLAIN challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PlainChallenge implements ChallengeInterface
{
    /**
     * @var PlainEncoder
     */
    protected $encoder;

    /**
     * @var SaslContext
     */
    protected $context;

    public function __construct(bool $isServerMode = false)
    {
        $this->encoder = new PlainEncoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    /**
     * {@inheritDoc}
     */
    public function challenge(?string $received = null, array $options = []): SaslContext
    {
        $received = $received === null ? null : $this->encoder->decode($received, $this->context);

        if ($this->context->isServerMode()) {
            return $this->serverProcess($received, $options);
        } else {
            return $this->clientProcess($options);
        }
    }

    protected function serverProcess(?Message $message, array $options): SaslContext
    {
        if ($message === null) {
            return $this->context;
        }
        if (!(isset($options['validate']) && is_callable($options['validate']))) {
            throw new SaslException('You must pass a callable validate option to the plain mechanism in server mode.');
        }
        $authzId = $message->get('authzid');
        $authcId = $message->get('authcid');
        $password = $message->get('password');

        $this->context->setIsComplete(true);
        $this->context->setIsAuthenticated((bool) $options['validate']($authzId, $authcId, $password));

        return $this->context;
    }

    protected function clientProcess(array $options): SaslContext
    {
        if (!isset($options['username'])) {
            throw new SaslException('You must supply a username for the PLAIN mechanism.');
        }
        if (!isset($options['password'])) {
            throw new SaslException('You must supply a password for the PLAIN mechanism.');
        }
        $message = new Message([
            'authzid' => $options['username'],
            'authcid' => $options['username'],
            'password' => $options['password'],
        ]);
        $this->context->setResponse($this->encoder->encode($message, $this->context));
        $this->context->setIsComplete(true);

        return $this->context;
    }
}
