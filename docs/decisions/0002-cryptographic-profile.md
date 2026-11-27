# ADR 0002: Cryptographic profile and envelope

- Status: Proposed, threat assumptions agreed; algorithm profile still undecided
- Decision: No wire protocol or cryptographic profile has been selected.
- Scope: This ADR compares candidate building blocks for the first .NET SDK and later browser and mobile clients.

## Requirements

The profile must support selected JSON HTTP bodies, authenticated encryption, strict algorithm allow-lists, API key rotation, a per-request response key, response-origin authentication, and implementations across .NET, browser and mobile platforms.

The API public key must be authenticated independently of a gateway that terminates TLS. Encryption must not be presented as caller authentication or replay protection.

## Candidates

| Candidate | Strengths | Design work still required |
| --- | --- | --- |
| JWE (RFC 7516) | Standard JSON serialisations, authenticated encryption, protected headers and additional authenticated data. .NET has documented JWE creation and decryption APIs. Browser Web Crypto provides ECDH and AES-GCM building blocks. | Select a narrow JWE profile; require protected headers and reject unrecognised algorithms. Confirm every target library interoperates, including key import, ECDH, KDF, serialization, response signing, and failure handling. |
| HPKE (RFC 9180) | A modern composition of KEM, KDF and AEAD with a clear encryption-context API and authenticated-data support. | HPKE does not define EnvelopeKit's HTTP JSON envelope, key identifiers, key discovery, replay fields, request/response correlation, or HTTP middleware semantics. Cross-platform SDK support must be confirmed. |

JWE specifies authenticated encryption and protected metadata, but does not authenticate the sender by itself. HPKE base mode has the same sender-authentication limitation. Neither standard supplies replay storage or authenticates an API key set for this deployment.

## Provisional recommendation

Prototype JWE first, because its JSON serialisation and existing .NET support may reduce implementation work across the first SDK and future clients. This is a recommendation to validate, not a final decision. The comparison should include a browser client and at least one mobile platform before the format is frozen.

A possible profile for evaluation is a single-recipient JWE using an approved ECDH-ES key-agreement mode with AES-GCM content encryption. The exact curve, key-management mode, content-encryption key size, serialization, protected headers, and response-signature construction remain undecided. The implementation must use a fixed allow-list and must not negotiate algorithms from untrusted input.

The request plaintext envelope would carry the application JSON, a fresh response public key, a request identifier, an expiry, and the data needed to bind the ciphertext to its HTTP method and target. The server response must be signed with a distinct API signing key and then encrypted to the request's one-use response public key. The API signing key's public counterpart must be authenticated through the key-discovery trust model. This requirement is agreed; the signature algorithm and exact nesting remain undecided.

## Required prototype before acceptance

- Encrypt and decrypt identical test vectors in .NET and browser JavaScript.
- Confirm signed key discovery, rotation, and trust-anchor behaviour when TLS terminates at a gateway. See ADR 0003.
- Confirm mandatory nested sign-then-encrypt response handling and signature-key rotation.
- Demonstrate strict algorithm allow-listing and rejection of malformed or modified envelopes.
- Measure message-size overhead and latency for representative JSON payloads.
- Document request replay storage, retries, and duplicate business-operation handling.

## References

- RFC 7516, JSON Web Encryption: https://www.rfc-editor.org/rfc/rfc7516
- RFC 7517, JSON Web Key: https://www.rfc-editor.org/rfc/rfc7517
- RFC 7518, JSON Web Algorithms: https://www.rfc-editor.org/rfc/rfc7518
- RFC 9180, Hybrid Public Key Encryption: https://www.rfc-editor.org/rfc/rfc9180
- RFC 9421, HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421
