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

use FreeDSx\Sasl\Encoder\ExternalEncoder;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\Options\ExternalOptions;
use FreeDSx\Sasl\SaslContext;

/**
 * The EXTERNAL challenge / response class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ExternalChallenge implements ChallengeInterface
{
    use ResolvesOptionsTrait;

    private ExternalEncoder $encoder;

    private SaslContext $context;

    public function __construct(bool $isServerMode = false)
    {
        $this->encoder = new ExternalEncoder();
        $this->context = new SaslContext();
        $this->context->setIsServerMode($isServerMode);
    }

    public function challenge(
        ?string $received = null,
        ?ChallengeOptionsInterface $options = null,
    ): SaslContext {
        $resolved = $this->resolveOptions(
            $options ?? new ExternalOptions(),
            ExternalOptions::class,
        );

        return $this->context->isServerMode()
            ? $this->serverProcess($received, $resolved)
            : $this->clientProcess($resolved);
    }

    /**
     * @throws SaslException
     */
    private function serverProcess(
        ?string $received,
        ExternalOptions $options,
    ): SaslContext {
        $validate = $options->getValidate();
        if ($validate === null) {
            throw new SaslException('You must pass a callable validate option to the external mechanism in server mode.');
        }

        // The credential is the verified peer identity from a lower layer; the payload is only the optional authzId.
        $rawAuthzId = $this->encoder->decode($received ?? '', $this->context)->get(SaslContext::AUTHZID);
        $authzId = is_string($rawAuthzId)
            ? $rawAuthzId
            : null;

        $this->context->setIsComplete(true);
        $this->context->setIsAuthenticated($validate($authzId));
        $this->context->set(SaslContext::AUTHZID, $authzId);

        return $this->context;
    }

    private function clientProcess(ExternalOptions $options): SaslContext
    {
        $data = [];
        if ($options->getAuthzId() !== null) {
            $data[SaslContext::AUTHZID] = $options->getAuthzId();
        }

        $this->context->setResponse($this->encoder->encode(
            new Message($data),
            $this->context,
        ));
        $this->context->setIsComplete(true);
        $this->context->setIsAuthenticated(true);

        return $this->context;
    }
}
