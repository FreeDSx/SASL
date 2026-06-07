# SASL Mechanisms

This library provides the following SASL mechanisms. All mechanisms are registered by default; pass a `SaslOptions` with a `supported` list to restrict which are available.

Per-mechanism settings are configured with a typed options object from `FreeDSx\Sasl\Options\*`, passed to `challenge()`.

```php
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\SaslOptions;
use FreeDSx\Sasl\Sasl;

$sasl = new Sasl();

// Restrict to specific mechanisms
$sasl = new Sasl(new SaslOptions(supported: [
    MechanismName::SCRAM_SHA256,
    MechanismName::PLAIN,
]));

// Get a specific mechanism
$mechanism = $sasl->get(MechanismName::SCRAM_SHA256);

// Select the best mechanism from a server-advertised list
$mechanism = $sasl->select([
    MechanismName::SCRAM_SHA256,
    MechanismName::PLAIN,
    MechanismName::DIGEST_MD5,
]);
```

Each mechanism exposes a challenge object for the client or the server:

```php
$challenge = $mechanism->challenge();                 // client mode
$challenge = $mechanism->challenge(serverMode: true); // server mode
```

---

## ANONYMOUS

No authentication. Sends optional trace information to the server.

**Security:** No integrity, no privacy, no authentication.

**Client options** (`AnonymousOptions`):

| Setter             | Default | Description                              |
|--------------------|---------|------------------------------------------|
| `setTrace(string)` | `null`  | Optional trace string sent to the server |

```php
use FreeDSx\Sasl\Options\AnonymousOptions;

$challenge = $mechanism->challenge();
$response = $challenge->challenge(
    null,
    (new AnonymousOptions())->setTrace('guest@example.com'),
);

// $response->isComplete() === true after one round
```

---

## EXTERNAL

The identity is established at a lower layer (e.g. a TLS client certificate); the SASL exchange carries no credential of its own. A single client-first round with an optional authorization identity (authzId). The server derives the identity from the lower-layer credential and validates via a callback.

**Security:** Authenticates using credentials established externally (e.g. TLS). Provides no integrity or privacy layer itself — the lower layer does.

**Client options** (`ExternalOptions`):

| Setter                | Default | Description                                |
|-----------------------|---------|--------------------------------------------|
| `setAuthzId(?string)` | `null`  | Optional authorization identity to request |

**Server options** (`ExternalOptions`):

| Setter                 | Default      | Description                       |
|------------------------|--------------|-----------------------------------|
| `setValidate(Closure)` | *(required)* | `Closure(?string $authzId): bool` |

```php
use FreeDSx\Sasl\Options\ExternalOptions;

// Client (optionally request an authzId)
$challenge = $mechanism->challenge();
$response = $challenge->challenge(
    null,
    (new ExternalOptions())->setAuthzId('dn:cn=user'),
);

// Server (the credential comes from the lower layer; validate the optional authzId)
$challenge = $mechanism->challenge(serverMode: true);
$response = $challenge->challenge(
    $received,
    (new ExternalOptions())->setValidate(
        fn (?string $authzId): bool => authorizeExternalIdentity($authzId),
    ),
);

// $response->isComplete() === true after one round
```

---

## PLAIN

Sends credentials as plaintext. Use only over TLS.

**Security:** Authenticates but transmits password in plaintext.

**Client options** (`PlainOptions`):

| Setter                | Default      | Description             |
|-----------------------|--------------|-------------------------|
| `setUsername(string)` | *(required)* | Authentication identity |
| `setPassword(string)` | *(required)* | User password           |

**Server options** (`PlainOptions`):

| Setter                 | Default      | Description                                                           |
|------------------------|--------------|----------------------------------------------------------------------|
| `setValidate(Closure)` | *(required)* | `Closure(?string $authzId, string $authcId, string $password): bool` |

```php
use FreeDSx\Sasl\Options\PlainOptions;

// Client
$challenge = $mechanism->challenge();
$response = $challenge->challenge(
    null,
    (new PlainOptions())
        ->setUsername('user')
        ->setPassword('secret'),
);

// Server
$challenge = $mechanism->challenge(serverMode: true);
$response = $challenge->challenge(
    $received,
    (new PlainOptions())->setValidate(
        fn (?string $authzId, string $authcId, string $password): bool => $password === getPassword($authcId),
    ),
);
```

---

## CRAM-MD5

> [!WARNING]
> CRAM-MD5 is included for legacy interoperability only. It relies on MD5 and offers no mutual authentication or security layer. Prefer a SCRAM-SHA-* mechanism for new integrations.

Server sends a challenge; a client responds with an HMAC-MD5 digest. Two-round exchange.

**Security:** Authenticates without transmitting the password in plaintext.

**Client options** (`CramMD5Options`):

| Setter                | Default      | Description   |
|-----------------------|--------------|---------------|
| `setUsername(string)` | *(required)* | Username      |
| `setPassword(string)` | *(required)* | User password |

**Server options** (`CramMD5Options`):

| Setter                         | Default              | Description                                                               |
|--------------------------------|----------------------|--------------------------------------------------------------------------|
| `setChallenge(string)`         | random 32-byte nonce | Override the server challenge string                                      |
| `setPasswordCallback(Closure)` | *(required)*         | `Closure(string $username, string $challenge): string` — expected digest |

```php
use FreeDSx\Sasl\Options\CramMD5Options;

// Client (round 1: receive challenge, round 2: send response)
$challenge = $mechanism->challenge();
$response = $challenge->challenge(
    $serverChallenge,
    (new CramMD5Options())
        ->setUsername('user')
        ->setPassword('secret'),
);
```

---

## DIGEST-MD5

> [!WARNING]
> DIGEST-MD5 is included for legacy interoperability only. RFC 2831 has been obsoleted (RFC 6331) and the mechanism relies on MD5. Prefer a SCRAM-SHA-* mechanism for new integrations.

Multi-round MD5-based authentication with optional integrity and privacy security layers. Implements RFC 2831.

**Security:** Authenticates without plaintext password. Optionally provides integrity (`auth-int`) or privacy (`auth-conf`) security layers.

**Client options** (`DigestMD5Options`):

| Setter                  | Default      | Description                                       |
|-------------------------|--------------|---------------------------------------------------|
| `setUsername(string)`   | *(required)* | Username                                          |
| `setPassword(string)`   | *(required)* | User password                                     |
| `setHost(string)`       | `null`       | Hostname for the digest-uri                       |
| `setRealm(string)`      | `null`       | Authentication realm                              |
| `setUseIntegrity(bool)` | `false`      | Enable integrity layer (`qop=auth-int`)           |
| `setUsePrivacy(bool)`   | `false`      | Enable privacy/encryption layer (`qop=auth-conf`) |
| `setService(string)`    | `'ldap'`     | SASL service name                                 |
| `setCnonce(string)`     | random       | Client nonce                                      |
| `setCipher(string)`     | auto         | Cipher for privacy (e.g. `'rc4'`, `'3des'`)       |

**Server options** (`DigestMD5Options`):

| Setter                  | Default      | Description                                       |
|-------------------------|--------------|---------------------------------------------------|
| `setPassword(string)`   | *(required)* | User password used to verify the client response  |
| `setUseIntegrity(bool)` | `false`      | Offer integrity layer                             |
| `setUsePrivacy(bool)`   | `false`      | Offer privacy layer                              |
| `setService(string)`    | `'ldap'`     | SASL service name                                 |
| `setNonce(string)`      | random       | Override the server nonce                         |

```php
use FreeDSx\Sasl\Options\DigestMD5Options;

$challenge = $mechanism->challenge();
$response = $challenge->challenge(
    $serverMessage,
    (new DigestMD5Options())
        ->setUsername('user')
        ->setPassword('secret')
        ->setHost('ldap.example.com')
        ->setService('ldap'),
);
```

---

## SCRAM-SHA-* (RFC 5802 / RFC 7677)

Modern salted challenge-response mechanisms using PBKDF2 key derivation and HMAC signatures. Mutual authentication: the client also verifies the server. `-PLUS` variants add TLS channel binding.

**Available mechanisms:**

| Mechanism             | Hash Algorithm | Channel Binding |
|-----------------------|----------------|-----------------|
| `SCRAM-SHA-1`         | SHA-1          | No              |
| `SCRAM-SHA-1-PLUS`    | SHA-1          | Yes             |
| `SCRAM-SHA-224`       | SHA-224        | No              |
| `SCRAM-SHA-224-PLUS`  | SHA-224        | Yes             |
| `SCRAM-SHA-256`       | SHA-256        | No              |
| `SCRAM-SHA-256-PLUS`  | SHA-256        | Yes             |
| `SCRAM-SHA-384`       | SHA-384        | No              |
| `SCRAM-SHA-384-PLUS`  | SHA-384        | Yes             |
| `SCRAM-SHA-512`       | SHA-512        | No              |
| `SCRAM-SHA-512-PLUS`  | SHA-512        | Yes             |
| `SCRAM-SHA3-512`      | SHA3-512       | No              |
| `SCRAM-SHA3-512-PLUS` | SHA3-512       | Yes             |

**Security:** Authenticates without transmitting the password. Resistant to replay and server-impersonation attacks. Use `-PLUS` variants with TLS channel binding for the strongest guarantee.

### Client options (`ScramOptions`)

**Round 1 (client-first):**

| Setter                 | Default         | Description                                     |
|------------------------|-----------------|-------------------------------------------------|
| `setUsername(string)`  | *(required)*    | Username (`=` and `,` are encoded per RFC 5802) |
| `setCnonce(string)`    | 24 random bytes | Client nonce                                    |
| `setCbindType(string)` | `'tls-unique'`  | Channel binding type (for `-PLUS` variants)     |

**Round 2 (client-final):**

| Setter                 | Default      | Description                                     |
|------------------------|--------------|-------------------------------------------------|
| `setPassword(string)`  | *(required)* | User password                                   |
| `setCbindData(string)` | `''`         | Raw channel binding data (for `-PLUS` variants) |

### Server options (`ScramOptions`)

**Round 1 (server-first):**

| Setter                | Default         | Description                          |
|-----------------------|-----------------|--------------------------------------|
| `setNonce(string)`    | 24 random bytes | Server portion of the combined nonce |
| `setSalt(string)`     | 16 random bytes | PBKDF2 salt (raw binary)             |
| `setIterations(int)`  | `4096`          | PBKDF2 iteration count               |

**Round 2 (server-final):**

| Setter                | Default      | Description                              |
|-----------------------|--------------|------------------------------------------|
| `setPassword(string)` | *(required)* | User password to verify the client proof |

### Example (client)

```php
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ScramOptions;

$mechanism = $sasl->get(MechanismName::SCRAM_SHA256);
$challenge = $mechanism->challenge();

// Round 1: send client-first message
$response = $challenge->challenge(null, (new ScramOptions())->setUsername('user'));
$clientFirst = $response->getResponse();

// Round 2: receive server-first, send client-final with password
$response = $challenge->challenge($serverFirst, (new ScramOptions())->setPassword('secret'));
$clientFinal = $response->getResponse();

// Round 3: receive server-final, verify server signature
$response = $challenge->challenge($serverFinal);
// $response->isComplete() === true
```

---

## Security Strength Summary

| Mechanism   | Authentication | Integrity Layer | Privacy Layer | Plaintext Password |
|-------------|:--------------:|:---------------:|:-------------:|:------------------:|
| ANONYMOUS   |       No       |       No        |      No       |         No         |
| EXTERNAL    | Yes (external) |       No        |      No       |         No         |
| PLAIN       |      Yes       |       No        |      No       |      **Yes**       |
| CRAM-MD5    |      Yes       |       No        |      No       |         No         |
| DIGEST-MD5  |      Yes       |    Optional     |   Optional    |         No         |
| SCRAM-SHA-* |  Yes (mutual)  |       No        |      No       |         No         |

For new integrations, prefer `SCRAM-SHA-256` or higher over `PLAIN`, `CRAM-MD5`, and `DIGEST-MD5`.

Always use SCRAM or PLAIN over a TLS-protected connection.
