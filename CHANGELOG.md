CHANGELOG
=========

0.2.0 (2026-03-22)
------------------
* Fix CRAM-MD5 server challenge to store the encoded challenge string (e.g. `<nonce>`) in the SASL context rather than the raw nonce, so the password callable receives the value the client used for its HMAC per RFC 2195.

0.1.1 (2019-12-09)
------------------
* Add an option to set the host section of the digest-uri for DIGEST-MD5. Mostly for easier AD support.

0.1.0 (2019-12-07)
------------------
* Initial release.
