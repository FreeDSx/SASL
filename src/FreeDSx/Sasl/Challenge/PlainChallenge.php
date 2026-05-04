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

use FreeDSx\Sasl\Encoder\PlainEncoder;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\Options\PlainOptions;
use FreeDSx\Sasl\SaslContext;

/**
 * The PLAIN challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PlainChallenge implements ChallengeInterface
{
    use ResolvesOptionsTrait;

    private PlainEncoder $encoder;

    private SaslContext $context;

    public function __construct(bool $isServerMode = false)
    {
        $this->encoder = new PlainEncoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    public function challenge(
        ?string $received = null,
        ?ChallengeOptionsInterface $options = null,
    ): SaslContext {
        $resolved = $this->resolveOptions(
            $options,
            PlainOptions::class,
        );
        $message = $received === null ? null : $this->encoder->decode($received, $this->context);

        return $this->context->isServerMode()
            ? $this->serverProcess($message, $resolved)
            : $this->clientProcess($resolved);
    }

    /**
     * @throws SaslException
     */
    private function serverProcess(
        ?Message $message,
        PlainOptions $options,
    ): SaslContext {
        if ($message === null) {
            return $this->context;
        }
        if ($options->getValidate() === null) {
            throw new SaslException('You must pass a callable validate option to the plain mechanism in server mode.');
        }
        $authzId = $message->get('authzid');
        $authcId = $message->get('authcid');
        $password = $message->get('password');

        $this->context->setIsComplete(true);
        $this->context->setIsAuthenticated((bool) ($options->getValidate())($authzId, $authcId, $password));

        return $this->context;
    }

    /**
     * @throws SaslException
     */
    private function clientProcess(PlainOptions $options): SaslContext
    {
        if ($options->getUsername() === null) {
            throw new SaslException('You must supply a username for the PLAIN mechanism.');
        }
        if ($options->getPassword() === null) {
            throw new SaslException('You must supply a password for the PLAIN mechanism.');
        }
        $message = new Message([
            'authzid' => $options->getUsername(),
            'authcid' => $options->getUsername(),
            'password' => $options->getPassword(),
        ]);
        $this->context->setResponse($this->encoder->encode($message, $this->context));
        $this->context->setIsComplete(true);

        return $this->context;
    }
}
