# Protocol design draft

**Status: design draft.** JWE has been selected as the message-encryption format. This document proposes message shapes and links to the key-manifest and replay rules for review. It is not a normative wire specification, and no implementation is ready for real data.

## Protocol layers

- HTTPS remains mandatory for transport security and API authentication.
- JWE protects selected JSON request and response bodies from forwarding infrastructure.
- JWS authenticates API responses before they are encrypted.
- A signed, versioned key manifest lets clients authenticate the API's encryption and response-verification keys using the root public key configured by the application.
- API authentication and authorisation remain separate from payload encryption.

## Key manifest and key rotation

The application configures a trusted API root public key. The API publishes a signed manifest with public operational keys. Clients verify the JWS against the configured root and validate issuer, audience, freshness, version, key purpose, and algorithm before using any key. Planned rotation uses a signed manifest that overlaps old and new public keys. Emergency revocation cannot reach offline clients until they refresh or their cached manifest expires.

The proposed schema, validation rules, freshness model, rotation procedure, and recovery limits are in [Key manifest and replay protection proposal](key-manifest-and-replay.md). The schema remains provisional.

## Request message proposal

The client creates a fresh response key pair for each protected request. It encrypts an inner JSON request envelope to the API's current public encryption key using JWE.

The decrypted request envelope is proposed to contain:

| Field | Purpose |
| --- | --- |
| `version` | Envelope protocol version |
| `requestId` | Random unique identifier for replay detection |
| `issuedAt`, `expiresAt` | Request freshness window |
| `method`, `target` | Context to compare with the actual HTTP request |
| `responsePublicKey` | One-use public key to which the API encrypts its response |
| `body` | The application's JSON request body |

The API validates that method and target match the actual HTTP request. It authenticates and authorises the caller using the application's existing mechanisms. It decrypts and validates the envelope before endpoint processing. Exact field names, canonical target rules, timestamp tolerance, body limits, and content type remain to be specified.

## Response message proposal

The API creates a response envelope containing the protocol version, request identifier, HTTP status, content type, and application JSON response body. It signs this response envelope with a response-signing key from the trusted manifest, then encrypts the signed result to the one-use response public key from the request.

The client decrypts the response, verifies the API signature and key purpose, checks the request identifier, and only then returns the JSON response to the calling application. The initial prototype uses compact JWS nested inside compact JWE. This round trip passed between .NET and the browser-compatible JavaScript JOSE library under Node.js 24. The actual Chromium run in CI has passed. Mobile engine checks remain outstanding before those serialisations and the candidate algorithm profile can be frozen.

Responses for requests rejected before the client response key can be trusted need generic failure handling. Error messages must not expose plaintext, key material, decryption internals, or unnecessary validation distinctions.

## Replay and retry

Replay protection uses a shared, atomic store. The replay key is scoped to the authenticated caller and API audience, not to an identity claimed only inside the encrypted request. The API records a valid request identifier before invoking application processing. Store failure is fail-closed. A duplicate attempt is rejected without invoking the endpoint.

Each retry uses a new protocol request identifier and a fresh one-use response key. Application idempotency remains a separate mechanism for preventing duplicate business actions after an uncertain outcome. These rules and the proposed store operation are detailed in [Key manifest and replay protection proposal](key-manifest-and-replay.md).

## Decisions still required

1. JWE and JWS serialisations for the HTTP body and nested response.
2. The interoperable algorithm profile, including key curve and signature algorithm.
3. Concrete manifest freshness, cache, clock-skew, and maximum request-lifetime defaults.
4. Canonical HTTP target rules and which headers, if any, are cryptographically bound.
5. Exact replay-store .NET interface, error behaviour, and duplicate-response mapping.
6. Which routes and JSON media types are protected by default.

See [ADR 0002](decisions/0002-cryptographic-profile.md) for the accepted JWE decision and remaining profile work, and [ADR 0003](decisions/0003-key-discovery.md) for the accepted trust model.
