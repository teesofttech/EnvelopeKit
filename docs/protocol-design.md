# Protocol design draft

**Status: design draft.** JWE has been selected as the message-encryption format. This document proposes message and key-manifest shapes for review. It is not a normative wire specification, and no implementation is ready for real data.

## Protocol layers

- HTTPS remains mandatory for transport security and API authentication.
- JWE protects selected JSON request and response bodies from forwarding infrastructure.
- JWS authenticates API responses before they are encrypted.
- A signed, versioned key manifest lets clients authenticate the API's encryption and response-verification keys using the root public key configured by the application.
- API authentication and authorisation remain separate from payload encryption.

## Key manifest proposal

The application configures a trusted root public key for its API. The API publishes a signed manifest containing only public operational keys.

Candidate manifest fields:

| Field | Purpose |
| --- | --- |
| `issuer` | Identifies the API that issued the manifest |
| `audience` | Binds the manifest to the configured API/application |
| `version` | Monotonically increasing manifest version |
| `issuedAt`, `expiresAt` | Freshness window |
| `keys` | Public encryption and response-verification keys |

Each key should have a unique `kid`, a declared purpose (`enc` or `sig`), an allow-listed algorithm, and validity dates. Private key material must never appear in the manifest. The root key signs the manifest. The exact schema and JWS representation remain open. The current prototype uses P-256 and a compact JWS signature, but these details remain provisional pending broader runtime checks.

Clients should reject invalid signatures, wrong issuer or audience, expired manifests, duplicate key identifiers, key-purpose mismatches, unsupported algorithms, and detectable rollback. Key rotation should publish old and new public keys together for a controlled overlap. Emergency revocation and root-key replacement procedures still need definition.

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

The client decrypts the response, verifies the API signature and key purpose, checks the request identifier, and only then returns the JSON response to the calling application. The initial prototype uses compact JWS nested inside compact JWE. This round trip passed between .NET and the browser-compatible JavaScript JOSE library under Node.js 24. Actual browser and mobile engine checks remain outstanding before those serialisations and the candidate algorithm profile can be frozen.

Responses for requests rejected before the client response key can be trusted need generic failure handling. Error messages must not expose plaintext, key material, decryption internals, or unnecessary validation distinctions.

## Replay and retry proposal

- Replay state must be shared and atomically written across API instances.
- The replay key should be scoped to the authenticated caller and request identifier.
- The API rejects a duplicate request identifier within its accepted validity window.
- A timestamp without a replay store does not prevent duplicate processing.
- A retry creates a new protocol request identifier and fresh response key.
- Business idempotency is separate. Applications should use an idempotency key for operations that must not execute twice after a failed or uncertain response.
- The protocol and middleware must define what happens if the replay record is stored but application processing fails.

## Decisions still required

1. JWE and JWS serialisations for the HTTP body and nested response.
2. The interoperable algorithm profile, including key curve and signature algorithm.
3. The exact signed manifest schema, trust-root signature format, freshness window, and rollback policy.
4. Canonical HTTP target rules and which headers, if any, are cryptographically bound.
5. Replay retention, distributed store interface, error behaviour, and retry policy.
6. Which routes and JSON media types are protected by default.

See [ADR 0002](../decisions/0002-cryptographic-profile.md) for the accepted JWE decision and remaining profile work.
