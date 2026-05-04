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

## Options arrays replaced by typed DTOs

All `array $options` parameters have been replaced by typed DTO objects from the `FreeDSx\Sasl\Options` namespace.

### `Sasl` constructor

```php
// before
new Sasl(['supported' => [MechanismName::DIGEST_MD5]]);

// after
use FreeDSx\Sasl\Options\SaslOptions;

new Sasl(new SaslOptions(supported: [MechanismName::DIGEST_MD5]));
```

### `Sasl::select()` / `MechanismSelector::select()`

```php
// before
$sasl->select($choices, ['use_integrity' => true]);
$sasl->select($choices, ['use_privacy' => true]);

// after
use FreeDSx\Sasl\Options\SelectOptions;

$sasl->select($choices, (new SelectOptions())->setUseIntegrity(true));
$sasl->select($choices, (new SelectOptions())->setUsePrivacy(true));
```

### `ChallengeInterface::challenge()`

The second parameter changed from `array $options = []` to `?ChallengeOptionsInterface $options = null`. Pass the mechanism-specific DTO, or omit the argument entirely when no options are needed.

Passing a DTO of the wrong type throws a `SaslException`.

#### ANONYMOUS

```php
// before
$challenge->challenge(null, ['trace' => 'user@example.com']);

// after
use FreeDSx\Sasl\Options\AnonymousOptions;

$challenge->challenge(null, (new AnonymousOptions())->setTrace('user@example.com'));
```

The `username` key alias accepted by the old array has been removed. Use `setTrace()` instead.

#### PLAIN

```php
// before — client
$challenge->challenge(null, ['username' => 'alice', 'password' => 'secret']);

// before — server
$challenge->challenge($received, ['validate' => $fn]);

// after — client
use FreeDSx\Sasl\Options\PlainOptions;

$challenge->challenge(null, (new PlainOptions())->setUsername('alice')->setPassword('secret'));

// after — server
$challenge->challenge($received, (new PlainOptions())->setValidate($fn));
```

#### CRAM-MD5

The server-side callable was previously passed under the `password` key (conflicting with the client's string password). It is now `setPasswordCallback()`.

```php
// before — client
$challenge->challenge($received, ['username' => 'alice', 'password' => 'secret']);

// before — server (generate challenge with fixed nonce)
$challenge->challenge(null, ['challenge' => 'mynonce']);

// before — server (validate)
$challenge->challenge($received, ['password' => $callable]);

// after — client
use FreeDSx\Sasl\Options\CramMD5Options;

$challenge->challenge($received, (new CramMD5Options())->setUsername('alice')->setPassword('secret'));

// after — server (generate challenge with fixed nonce)
$challenge->challenge(null, (new CramMD5Options())->setChallenge('mynonce'));

// after — server (validate)
$challenge->challenge($received, (new CramMD5Options())->setPasswordCallback($callable));
```

#### SCRAM

```php
// before — client-first
$challenge->challenge(null, ['username' => 'alice', 'cnonce' => $cnonce]);

// before — client-final
$challenge->challenge($serverFirst, ['password' => 'secret']);

// before — server-first
$challenge->challenge($clientFirst, ['nonce' => $snonce, 'salt' => $salt, 'iterations' => 4096]);

// before — server-final
$challenge->challenge($clientFinal, ['password' => 'secret']);

// after
use FreeDSx\Sasl\Options\ScramOptions;

$challenge->challenge(null, (new ScramOptions())->setUsername('alice')->setCnonce($cnonce));
$challenge->challenge($serverFirst, (new ScramOptions())->setPassword('secret'));
$challenge->challenge($clientFirst, (new ScramOptions())->setNonce($snonce)->setSalt($salt)->setIterations(4096));
$challenge->challenge($clientFinal, (new ScramOptions())->setPassword('secret'));
```

`cbind_type` → `setCbindType()`, `cbind_data` → `setCbindData()`.

#### DIGEST-MD5

```php
// before
$challenge->challenge($received, [
    'use_privacy'  => true,
    'use_integrity' => false,
    'username'     => 'alice',
    'password'     => 'secret',
    'host'         => 'ldap.example.com',
    'nonce_size'   => 32,
]);

// after
use FreeDSx\Sasl\Options\DigestMD5Options;

$challenge->challenge($received, (new DigestMD5Options())
    ->setUsePrivacy(true)
    ->setUsername('alice')
    ->setPassword('secret')
    ->setHost('ldap.example.com')
    ->setNonceSize(32));
```

Key renames: `use_integrity` → `setUseIntegrity()`, `use_privacy` → `setUsePrivacy()`, `nonce_size` → `setNonceSize()`.
