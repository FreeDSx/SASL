CHANGELOG
=========

1.0.0 (2026-XX-XX)
------------------
* Raise the minimum PHP version to 8.2.
* Introduce strict types, typed properties, and `final` across classes.
* Replace mechanism-name string constants with the `MechanismName` backed enum (see UPGRADE-1.0.md).
* Replace SCRAM hash-algorithm string constants with the `HashAlgorithm` enum.
* Replace DIGEST-MD5 message-type integer constants with the `DigestMD5MessageType` enum.
* Replace DIGEST-MD5 cipher string keys with the `DigestMD5Cipher` enum.
* Replace all `array $options` parameters with typed options DTOs (see UPGRADE-1.0.md).

0.2.1 (2026-03-22)
------------------
* Allow specifying server vs client mode when creating a challenge.

0.2.0 (2026-03-22)
------------------
* Fix CRAM-MD5 server challenge to store the encoded challenge string (e.g. `<nonce>`) in the SASL context rather than the raw nonce, so the password callable receives the value the client used for its HMAC per RFC 2195.
* Add SCRAM support (RFC 5802 / RFC 7677) covering all standard variants: SCRAM-SHA-1, SCRAM-SHA-224, SCRAM-SHA-256, SCRAM-SHA-384, SCRAM-SHA-512, SCRAM-SHA3-512, and their respective `-PLUS` channel-binding counterparts.

0.1.1 (2019-12-09)
------------------
* Add an option to set the host section of the digest-uri for DIGEST-MD5. Mostly for easier AD support.

0.1.0 (2019-12-07)
------------------
* Initial release.
