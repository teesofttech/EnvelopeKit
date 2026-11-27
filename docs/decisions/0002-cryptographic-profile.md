# ADR 0002: Cryptographic profile and envelope

- Status: Accepted for JWE; serialisation and algorithm profile remain open
- Decision: Use JWE (RFC 7516) as EnvelopeKit's message-encryption format. Use JWS (RFC 7515) to authenticate API responses, signing the response envelope before encrypting it as JWE. No custom cryptographic primitives will be introduced.
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

## Decision and profile boundary

JWE is selected as the protocol family. This does not freeze a particular JWE serialisation, key curve, JWE algorithm suite, JWS algorithm, or manifest schema. Those choices require an interoperability check in .NET and browser JavaScript, followed by a mobile compatibility check before the wire profile is published as stable.

The first candidate profile is single-recipient compact JWE using ECDH-ES with A256GCM, plus compact JWS using ES256 for API responses. The .NET-to-JavaScript interoperability spike has passed with P-256 keys in Node.js and headless Chromium in GitHub Actions. Keep the profile provisional until at least one mobile platform is checked and the production JOSE dependency is selected. The implementation must use fixed allow-lists and must not negotiate algorithms from untrusted input.

The request plaintext envelope would carry the application JSON, a fresh response public key, a request identifier, an expiry, and the data needed to bind the ciphertext to its HTTP method and target. The server response must be signed with a distinct API signing key and then encrypted to the request's one-use response public key. The API signing key's public counterpart must be authenticated through the key-discovery trust model. This requirement is agreed; the signature algorithm and exact nesting remain undecided.

## Interoperability evidence and remaining work

The prototype at [prototypes/jwe-interop](../prototypes/jwe-interop/README.md) passed a compact JWE round trip between .NET `jose-jwt` 5.3.0 and the browser-compatible Web API implementation in JavaScript `jose` 6.2.16, run under Node.js 24. It also passed .NET JWS ES256 signing with JavaScript verification, and rejected a modified JWE authentication tag. This is useful evidence, but the Node.js check is not an actual browser engine test. The headless Chromium run in CI has passed, so browser-engine interoperability is verified for this candidate. No mobile runtime has been checked. The prototype library versions are not production dependency decisions.

Microsoft IdentityModel 8.23.0 is not currently a drop-in implementation for this candidate: its public issue tracker documents direct ECDH-ES handler limitations and ECDH-ES+A*KW with AES-GCM incompatibility. Reassess this before choosing a production .NET JOSE dependency.

Before freezing the wire profile:

- Repeat the scenario in a real browser engine and at least one mobile runtime.
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
