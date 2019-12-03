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

use FreeDSx\Sasl\Encoder\AnonymousEncoder;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;

/**
 * The ANONYMOUS challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AnonymousChallenge implements ChallengeInterface
{
    /**
     * @var SaslContext
     */
    protected $context;

    /**
     * @var AnonymousEncoder
     */
    protected $encoder;

    public function __construct(bool $isServerMode = false)
    {
        $this->encoder = new AnonymousEncoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    /**
     * {@inheritDoc}
     */
    public function challenge(?string $received = null, array $options = []): SaslContext
    {
        if ($this->context->isServerMode()) {
            $this->processServer($received);
        } else {
            $this->processClient($options);
        }

        return $this->context;
    }

    protected function processServer(?string $received): void
    {
        if ($received === null) {
            return;
        }
        $received = $this->encoder->decode($received, $this->context);

        $this->context->setIsComplete(true);
        $this->context->setIsAuthenticated(true);

        if ($received->has('trace')) {
            $this->context->set('trace', $received->get('trace'));
        }
    }

    protected function processClient(array $options): void
    {
        $data = [];

        if (isset($options['username']) || isset($options['trace'])) {
            $data['trace'] = $options['trace'] ?? $options['username'];
        }

        $this->context->setResponse($this->encoder->encode(new Message($data), $this->context));
        $this->context->setIsComplete(true);
        $this->context->setIsAuthenticated(true);
    }
}
