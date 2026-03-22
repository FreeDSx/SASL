# SASL Mechanisms

This library provides the following SASL mechanisms. All mechanisms are registered by default; use the `supported` option to restrict which are available.

```php
use FreeDSx\Sasl\Sasl;

$sasl = new Sasl();

// Restrict to specific mechanisms
$sasl = new Sasl(['supported' => ['SCRAM-SHA-256', 'PLAIN']]);

// Get a specific mechanism
$mechanism = $sasl->get('SCRAM-SHA-256');

// Select the best mechanism from a server-advertised list
$mechanism = $sasl->select(['SCRAM-SHA-256', 'PLAIN', 'DIGEST-MD5']);
```

---

## ANONYMOUS

No authentication. Sends optional trace information to the server.

**Security:** No integrity, no privacy, no authentication.

**Client options:**

| Option     | Default | Description                              |
|------------|---------|------------------------------------------|
| `username` | `null`  | Optional trace string sent to the server |

```php
$challenge = $mechanism->challenge();

$response = $challenge->challenge(
    null,
    ['username' => 'guest@example.com']
);

// $response->isComplete() === true after one round
```

---

## PLAIN

Sends credentials as plaintext. Use only over TLS.

**Security:** Authenticates but transmits password in plaintext.

**Client options:**

| Option     | Default      | Description             |
|------------|--------------|-------------------------|
| `username` | *(required)* | Authentication identity |
| `password` | *(required)* | User password           |

**Server options:**

| Option     | Default      | Description                                                          |
|------------|--------------|----------------------------------------------------------------------|
| `validate` | *(required)* | `callable(string $authzid, string $authcid, string $password): bool` |

```php
// Client
$response = $challenge->challenge(null, [
    'username' => 'user',
    'password' => 'secret',
]);

// Server
$response = $challenge->challenge($received, [
    'validate' => fn($authzid, $authcid, $password) => $password === getPassword($authcid),
]);
```

---

## CRAM-MD5

Server sends a challenge; a client responds with an HMAC-MD5 digest. Two-round exchange.

**Security:** Authenticates without transmitting the password in plaintext.

**Client options:**

| Option     | Default      | Description   |
|------------|--------------|---------------|
| `username` | *(required)* | Username      |
| `password` | *(required)* | User password |

**Server options:**

| Option      | Default              | Description                                                                       |
|-------------|----------------------|-----------------------------------------------------------------------------------|
| `challenge` | random 32-byte nonce | Override the server challenge string                                              |
| `password`  | *(required)*         | `callable(string $username, string $challenge): string` — returns expected digest |

```php
// Client (round 1: receive challenge, round 2: send response)
$response = $challenge->challenge($serverChallenge, [
    'username' => 'user',
    'password' => 'secret',
]);
```

---

## DIGEST-MD5

Multi-round MD5-based authentication with optional integrity and privacy security layers. Implements RFC 2831.

**Security:** Authenticates without plaintext password. Optionally provides integrity (`auth-int`) or privacy (`auth-conf`) security layers.

**Client options:**

| Option          | Default      | Description                                       |
|-----------------|--------------|---------------------------------------------------|
| `username`      | *(required)* | Username                                          |
| `password`      | *(required)* | User password                                     |
| `host`          | `null`       | Hostname for the digest-uri                       |
| `realm`         | `null`       | Authentication realm                              |
| `use_integrity` | `false`      | Enable integrity layer (`qop=auth-int`)           |
| `use_privacy`   | `false`      | Enable privacy/encryption layer (`qop=auth-conf`) |
| `service`       | `'ldap'`     | SASL service name                                 |
| `cnonce`        | random       | Client nonce                                      |
| `cipher`        | auto         | Cipher for privacy (e.g. `'rc4'`, `'3des'`)       |

**Server options:**

| Option          | Default      | Description                              |
|-----------------|--------------|------------------------------------------|
| `validate`      | *(required)* | Callable to validate the client response |
| `use_integrity` | `false`      | Offer integrity layer                    |
| `use_privacy`   | `false`      | Offer privacy layer                      |
| `service`       | `'ldap'`     | SASL service name                        |
| `nonce`         | random       | Override the server nonce                |

```php
$response = $challenge->challenge($serverMessage, [
    'username' => 'user',
    'password' => 'secret',
    'host'     => 'ldap.example.com',
    'service'  => 'ldap',
]);
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

### Client options

**Round 1 (client-first):**

| Option       | Default         | Description                                     |
|--------------|-----------------|-------------------------------------------------|
| `username`   | *(required)*    | Username (`=` and `,` are encoded per RFC 5802) |
| `cnonce`     | 24 random bytes | Client nonce                                    |
| `cbind_type` | `'tls-unique'`  | Channel binding type (for `-PLUS` variants)     |

**Round 2 (client-final):**

| Option       | Default      | Description                                     |
|--------------|--------------|-------------------------------------------------|
| `password`   | *(required)* | User password                                   |
| `cbind_data` | `''`         | Raw channel binding data (for `-PLUS` variants) |

### Server options

**Round 1 (server-first):**

| Option       | Default         | Description                          |
|--------------|-----------------|--------------------------------------|
| `nonce`      | 24 random bytes | Server portion of the combined nonce |
| `salt`       | 16 random bytes | PBKDF2 salt (raw binary)             |
| `iterations` | `4096`          | PBKDF2 iteration count               |

**Round 2 (server-final):**

| Option     | Default      | Description                              |
|------------|--------------|------------------------------------------|
| `password` | *(required)* | User password to verify the client proof |

### Example (client)

```php
$mechanism = $sasl->get('SCRAM-SHA-256');
$challenge = $mechanism->challenge();

// Round 1: send client-first message
$response = $challenge->challenge(null, ['username' => 'user']);
$clientFirst = $response->get('response');

// Round 2: receive server-first, send client-final with password
$response = $challenge->challenge($serverFirst, ['password' => 'secret']);
$clientFinal = $response->get('response');

// Round 3: receive server-final, verify server signature
$response = $challenge->challenge($serverFinal, []);
// $response->isComplete() === true
```

---

## Security Strength Summary

| Mechanism   | Authentication | Integrity Layer | Privacy Layer | Plaintext Password |
|-------------|:--------------:|:---------------:|:-------------:|:------------------:|
| ANONYMOUS   |       No       |       No        |      No       |         No         |
| PLAIN       |      Yes       |       No        |      No       |      **Yes**       |
| CRAM-MD5    |      Yes       |       No        |      No       |         No         |
| DIGEST-MD5  |      Yes       |    Optional     |   Optional    |         No         |
| SCRAM-SHA-* |  Yes (mutual)  |       No        |      No       |         No         |

For new integrations, prefer `SCRAM-SHA-256` or higher over `PLAIN`, `CRAM-MD5`, and `DIGEST-MD5`.

Always use SCRAM or PLAIN over a TLS-protected connection.
