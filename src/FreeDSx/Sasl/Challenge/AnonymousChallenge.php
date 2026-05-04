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

namespace FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Encoder\AnonymousEncoder;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\Options\AnonymousOptions;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\SaslContext;

/**
 * The ANONYMOUS challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AnonymousChallenge implements ChallengeInterface
{
    use ResolvesOptionsTrait;

    private readonly SaslContext $context;

    private readonly AnonymousEncoder $encoder;

    public function __construct(bool $isServerMode = false)
    {
        $this->encoder = new AnonymousEncoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    public function challenge(
        ?string $received = null,
        ?ChallengeOptionsInterface $options = null,
    ): SaslContext {
        $resolved = $this->resolveOptions($options, AnonymousOptions::class);

        if ($this->context->isServerMode()) {
            $this->processServer($received);
        } else {
            $this->processClient($resolved);
        }

        return $this->context;
    }

    private function processServer(?string $received): void
    {
        if ($received === null) {
            return;
        }
        $message = $this->encoder->decode($received, $this->context);

        $this->context->setIsComplete(true);
        $this->context->setIsAuthenticated(true);

        if ($message->has('trace')) {
            $this->context->set('trace', $message->get('trace'));
        }
    }

    private function processClient(AnonymousOptions $options): void
    {
        $data = [];
        if ($options->getTrace() !== null) {
            $data['trace'] = $options->getTrace();
        }

        $this->context->setResponse($this->encoder->encode(new Message($data), $this->context));
        $this->context->setIsComplete(true);
        $this->context->setIsAuthenticated(true);
    }
}
