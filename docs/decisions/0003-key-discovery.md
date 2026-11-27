# ADR 0003: API key discovery and trust

- Status: Proposed
- Decision: No key-distribution mechanism has been accepted.
- Context: The agreed threat model includes a gateway that may replace the API's public key response. HTTPS to that gateway is not an independent trust anchor when it terminates TLS.

## Requirements

- The client must authenticate the API encryption public key before encrypting sensitive request bodies.
- The client must authenticate the API response-verification public key before accepting signed responses.
- Encryption and signing keys must have distinct purposes and identifiers.
- Rotation must allow planned overlap and support urgent revocation or replacement.
- Expired, untrusted, malformed, or rolled-back key material must fail closed.
- The .NET, browser, and mobile SDKs must consume the same documented key format and trust rules.

## Proposed model for evaluation

1. The application developer configures the API origin and a trust root public key or its fingerprint through a trusted application configuration path.
2. The API publishes a versioned key manifest. The manifest identifies encryption keys and response-verification keys by distinct key identifiers and explicit purpose.
3. The manifest is signed with a key chained to the configured trust root. The client verifies the signature and manifest scope before using any listed key.
4. Each encrypted request identifies the selected encryption key. Each signed response identifies the selected signing key.
5. Planned rotation publishes old and new keys together for a defined overlap. The API retains old private decryption keys only as long as accepted requests may still use them. Expired or revoked keys are rejected according to a documented policy.
6. Clients reject a manifest that is invalid or beyond its freshness window. Where the platform permits, clients retain the highest accepted manifest version to detect rollback.

The manifest format and signing arrangement should use established JWS/JWK mechanisms where suitable. JWK defines key purpose values such as `enc` and `sig`; the protocol should require explicit, separate purposes.

## Web client limitation

A browser SDK cannot defend against a gateway that can replace the JavaScript application using that SDK. Such code can read the plaintext before encryption, replace the configured trust root, or read plaintext after decryption. A browser client can make this protection claim only when the application code and root configuration are trusted independently of the gateway in scope.

If the web app and API share the same infrastructure trust boundary, EnvelopeKit must describe its browser protection as protection from passive body inspection, not from an active operator who can modify the application bundle. Native mobile SDKs can use trust configuration delivered with the signed application, but application compromise remains out of scope.

## Open decisions

- Is the trust root a single public key, a set of root keys, or a developer-supplied trust callback?
- Is the manifest a JWS object, or is there an existing signed metadata format that fits better?
- What freshness window and rollback policy work across mobile devices and browser sessions?
- How are root-key rotation, emergency compromise, and recovery handled?
- Does the SDK offer secure defaults while allowing applications to supply their own key store?

## References

- RFC 7515, JSON Web Signature: https://www.rfc-editor.org/rfc/rfc7515
- RFC 7517, JSON Web Key: https://www.rfc-editor.org/rfc/rfc7517
