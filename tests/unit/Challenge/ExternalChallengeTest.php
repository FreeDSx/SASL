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

namespace Tests\Unit\FreeDSx\Sasl\Challenge;

use FreeDSx\Sasl\Challenge\ExternalChallenge;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Options\ExternalOptions;
use PHPUnit\Framework\TestCase;

final class ExternalChallengeTest extends TestCase
{
    public function testTheClientChallengeWithAnAuthzId(): void
    {
        $context = (new ExternalChallenge())
            ->challenge(null, (new ExternalOptions())->setAuthzId('dn:cn=foo'));

        self::assertSame(
            'dn:cn=foo',
            $context->getResponse(),
        );
        self::assertTrue($context->isComplete());
    }

    public function testTheClientChallengeWithoutAnAuthzId(): void
    {
        $context = (new ExternalChallenge())
            ->challenge(null, new ExternalOptions());

        self::assertSame(
            '',
            $context->getResponse(),
        );
        self::assertTrue($context->isComplete());
    }

    public function testTheServerAuthenticatesWhenTheValidateCallbackPasses(): void
    {
        $challenge = new ExternalChallenge(true);
        $context = $challenge->challenge('', (new ExternalOptions())->setValidate(fn (?string $authzId): bool => true));

        self::assertTrue($context->isComplete());
        self::assertTrue($context->isAuthenticated());
        self::assertNull($context->getResponse());
    }

    public function testTheServerDoesNotAuthenticateWhenTheValidateCallbackFails(): void
    {
        $challenge = new ExternalChallenge(true);
        $context = $challenge->challenge('', (new ExternalOptions())->setValidate(fn (?string $authzId): bool => false));

        self::assertTrue($context->isComplete());
        self::assertFalse($context->isAuthenticated());
    }

    public function testTheServerPassesAProvidedAuthzIdToTheValidateCallback(): void
    {
        $received = 'unset';
        $challenge = new ExternalChallenge(true);
        $challenge->challenge('dn:cn=foo', (new ExternalOptions())->setValidate(
            function (?string $authzId) use (&$received): bool {
                $received = $authzId;

                return true;
            },
        ));

        self::assertSame('dn:cn=foo', $received);
    }

    public function testTheServerPassesNullToTheValidateCallbackWhenNoAuthzIdIsSent(): void
    {
        $received = 'unset';
        $challenge = new ExternalChallenge(true);
        $challenge->challenge('', (new ExternalOptions())->setValidate(
            function (?string $authzId) use (&$received): bool {
                $received = $authzId;

                return true;
            },
        ));

        self::assertNull($received);
    }

    public function testTheServerThrowsWithoutAValidateCallback(): void
    {
        $this->expectException(SaslException::class);

        (new ExternalChallenge(true))->challenge('');
    }
}
