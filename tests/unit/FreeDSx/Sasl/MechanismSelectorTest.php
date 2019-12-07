<?php

/**
 * This file is part of the FreeDSx SASL package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Sasl;

use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\AnonymousMechanism;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use FreeDSx\Sasl\MechanismSelector;
use PHPUnit\Framework\TestCase;

class MechanismSelectorTest extends TestCase
{
    /**
     * @var MechanismSelector
     */
    protected $selector;

    public function setUp()
    {
        parent::setUp();
        $this->selector = new MechanismSelector([
            new PlainMechanism(),
            new CramMD5Mechanism(),
            new AnonymousMechanism(),
            new DigestMD5Mechanism(),
        ]);
    }

    public function testSelectWithNoChoicesSpecified()
    {
        $choice = $this->selector->select();

        $this->assertEquals('DIGEST-MD5', $choice->getName());
    }

    public function testSelectWithAnonymousOrAuthOnly()
    {
        $choice = $this->selector->select(['CRAM-MD5', 'ANONYMOUS']);

        $this->assertEquals('CRAM-MD5', $choice->getName());
    }

    public function testSelectWithUseIntegrity()
    {
        $choice = $this->selector->select([], ['use_integrity' => true]);

        $this->assertEquals('DIGEST-MD5', $choice->getName());
    }

    public function testSelectWithUsePrivacy()
    {
        $choice = $this->selector->select([], ['use_integrity' => true]);

        $this->assertEquals('DIGEST-MD5', $choice->getName());
    }

    public function testSelectWithoutPrivacyOrIntegrityStillSelectsTheBetterChoiceForAuth()
    {
        $choice = $this->selector->select([], ['use_integrity' => false, 'use_privacy' => false]);

        $this->assertEquals('DIGEST-MD5', $choice->getName());
    }

    public function testSelectChoosesAuthChoicesCorrectly()
    {
        $choice = $this->selector->select(['ANONYMOUS', 'PLAIN', 'CRAM-MD5']);

        $this->assertEquals('CRAM-MD5', $choice->getName());
    }

    public function testSelectChoosesAuthOverAnon()
    {
        $choice = $this->selector->select(['ANONYMOUS', 'PLAIN']);

        $this->assertEquals('PLAIN', $choice->getName());
    }

    public function testSelectThrowsAnExceptionIfNoMechsMeetsIntegrityRequirements()
    {
        $this->expectException(SaslException::CLASS);

        $this->selector->select(['ANONYMOUS', 'PLAIN', 'CRAM-MD5'], ['use_integrity' => true]);
    }

    public function testSelectThrowsAnExceptionIfNoMechsMeetsPrivacyRequirements()
    {
        $this->expectException(SaslException::CLASS);

        $this->selector->select(['ANONYMOUS', 'PLAIN', 'CRAM-MD5'], ['use_privacy' => true]);
    }

    public function testSelectThrowsAnExceptionIfNoSupportedMechsAreFound()
    {
        $this->expectException(SaslException::CLASS);

        $this->selector->select(['FOO']);
    }
}
