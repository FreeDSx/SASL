Upgrading from 0.x to 1.0
=========================

## Mechanism names are now an enum

The `string` constants previously defined on each mechanism class have been replaced by the `FreeDSx\Sasl\Mechanism\MechanismName` backed enum.

| Old                                      | New                                                               |
|------------------------------------------|-------------------------------------------------------------------|
| `AnonymousMechanism::NAME`               | `MechanismName::ANONYMOUS`                                        |
| `PlainMechanism::NAME`                   | `MechanismName::PLAIN`                                            |
| `CramMD5Mechanism::NAME`                 | `MechanismName::CRAM_MD5`                                         |
| `DigestMD5Mechanism::NAME`               | `MechanismName::DIGEST_MD5`                                       |
| `ScramMechanism::SHA1` … `SHA3_512_PLUS` | `MechanismName::SCRAM_SHA1` … `SCRAM_SHA3_512_PLUS`               |
| `ScramMechanism::VARIANTS`               | `MechanismName::cases()` filtered with `MechanismName::isScram()` |

## `Sasl` registry takes enum values

```php
// before
$sasl->get('DIGEST-MD5');
$sasl->supports('SCRAM-SHA-256');
$sasl->remove('PLAIN');
$sasl->select(['SCRAM-SHA-256', 'PLAIN']);
new Sasl(['supported' => ['DIGEST-MD5']]);

// after
use FreeDSx\Sasl\Mechanism\MechanismName;

$sasl->get(MechanismName::DIGEST_MD5);
$sasl->supports(MechanismName::SCRAM_SHA256);
$sasl->remove(MechanismName::PLAIN);
$sasl->select([MechanismName::SCRAM_SHA256, MechanismName::PLAIN]);
new Sasl(['supported' => [MechanismName::DIGEST_MD5]]);
```

## Concrete classes are `final`

All concrete classes in the library are now marked `final`. If you were extending any of these, switch to composition instead.
