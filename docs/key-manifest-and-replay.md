# Key manifest and replay protection proposal

**Status: proposed design for review.** This document makes the next protocol decisions concrete. It is not a production specification. The wire format, algorithm profile, and default time windows remain provisional until the cross-runtime profile and implementation library are confirmed.

## 1. Signed API key manifest

### Trust model

The application configures a trusted API root public key, or its fingerprint, through a trusted configuration path. The API serves a signed manifest. Clients verify the manifest with that configured root before using any operational key. The manifest endpoint and HTTPS remain useful for delivery and transport security, but neither is the trust anchor.

The initial design uses one offline or tightly controlled root signing key to sign manifests directly. There is no online key chain or EnvelopeKit-operated key service in v1. Root-key replacement is an application configuration update and must be delivered through a separately trusted release or configuration channel. If the root is compromised, clients must not accept a replacement root supplied only by the same manifest endpoint.

### Representation

- The manifest is a compact JWS whose payload is UTF-8 JSON.
- The JWS protected header carries `typ: "application/envelopekit-key-manifest+jws"`, an allow-listed signing `alg`, and `kid` identifying the configured root key.
- The JWS payload contains the fields below. The JWS signature covers the exact payload bytes.
- Operational public keys are represented as public JWKs. Private JWK members, certificates containing private keys, and unknown critical parameters are rejected.
- The manifest is served with a fixed media type and fetched only from the API origin configured by the application. Redirects to another origin are rejected.

### Proposed payload schema

| Field | Type | Rule |
| --- | --- | --- |
| `iss` | string | Exact configured API issuer identifier |
| `aud` | string or array of strings | Must include the application/API audience configured by the developer |
| `version` | positive integer | Monotonically increases for every published manifest; never reused |
| `iat` | integer | Unix time at which this manifest was signed and published |
| `exp` | integer | Unix time after which this manifest is no longer accepted |
| `keys` | array | Public operational JWKs available during this manifest's validity period |

Each `keys` entry has:

| Field | Type | Rule |
| --- | --- | --- |
| `kid` | string | Unique within the manifest and stable for this key's lifetime |
| `use` | string | Exactly `enc` for request decryption keys or `sig` for response verification keys |
| `alg` | string | One algorithm permitted by the selected EnvelopeKit profile; never chosen dynamically from an untrusted message |
| `nbf` | integer | Earliest Unix time the client may use the key |
| `exp` | integer | Unix time after which the key must not be used |
| `jwk` | object | Public-only JWK whose key type, curve and declared use match the selected profile |

A manifest must not contain duplicate `kid` values. A key must be valid for the whole intended operation: clients do not encrypt to an expired or not-yet-valid key, and do not verify a response with a key outside its accepted validity. The API must keep an old decryption private key available for at least the maximum accepted request lifetime after the old public key stops being advertised. The API must retain response-verification public keys long enough for clients to verify responses to requests sent during the rotation overlap.

A `sig` key is for verifying API response JWS signatures. An `enc` key is for encrypting client requests to the API. The two purposes require distinct key pairs. The exact JWK `use`, `key_ops`, `alg`, and curve values must be made consistent with the eventual algorithm profile before this becomes normative.

### Client validation and freshness

A client accepts a manifest only if all of the following hold:

1. The JWS is well formed, uses an allowed root-signature algorithm, and verifies under the configured root key selected by the protected `kid`.
2. `typ`, `iss`, and `aud` match the expected values exactly.
3. `iat` is not unreasonably in the future, `exp` is after the current time, and `exp` is after `iat`.
4. `version` is positive and not lower than the highest version previously accepted for this issuer and audience.
5. All key identifiers are unique, keys are public-only, purposes and algorithms are allowed, and each key's validity interval is well formed.
6. The manifest is within the SDK's configured maximum freshness period.

The SDK should persist the highest accepted `version` when the platform offers durable trusted storage. If it has no remembered version, a valid root signature and a fresh `iat`/`exp` establish the initial state, but cannot prove that the manifest is the newest version. Clearing app state or changing devices also clears this local rollback memory. A later protocol version may define a stronger transparency or update mechanism; v1 does not claim global rollback detection across devices.

The manifest endpoint should publish a short-lived manifest and clients should cache it only until the earlier of its `exp` and the SDK's maximum cache age. The exact cache age and clock-skew allowance remain profile defaults to be set after mobile and browser constraints are reviewed. When refresh fails, a client may use a cached manifest only while it remains valid and within the configured freshness limit. Once stale, the SDK fails closed for protected calls.

### Planned and emergency rotation

For planned rotation, publish a higher-version manifest containing both the old and new public keys during an overlap. Begin using the new key only after the API can process it. Stop advertising the old key after clients have had an opportunity to refresh, but retain the old decryption private key through the maximum request lifetime and permitted clock skew. Keep old response-verification public keys available for responses still in flight.

For emergency compromise, publish a higher-version manifest that omits the compromised key and stop using that key immediately. A client with network access can learn the revocation when it refreshes. Offline clients cannot learn an emergency revocation before their cached manifest expires; this is a limitation of signed, cached discovery. Root-key compromise requires a trusted application configuration update, not a manifest signed by the compromised root.

## 2. Replay-prevention contract

### Request fields and validation order

The decrypted request envelope contains:

- `requestId`: 128-bit or stronger CSPRNG-generated value, encoded using the protocol's canonical text encoding.
- `issuedAt`: Unix time when this attempt was created.
- `expiresAt`: Unix time after which this attempt must not be accepted.
- The response public key and request context defined by the protocol design.

The API first authenticates and authorises the caller using the application's normal mechanism. It then decrypts the envelope and validates the protocol version, request context, timestamps, and body limits. It derives replay scope from the authenticated caller and configured API audience. It must not trust an identity, tenant, or replay scope supplied only inside the encrypted envelope.

Proposed time checks are:

- Reject if `issuedAt` is later than the server's current time plus the configured clock-skew allowance.
- Reject if `expiresAt` is not later than the server's current time minus that allowance.
- Reject if `expiresAt` is not later than `issuedAt`.
- Reject if the interval from `issuedAt` to `expiresAt` exceeds the profile's maximum request lifetime.

The first profile should choose concrete defaults for clock skew and maximum request lifetime. They must be short enough to bound replay retention and long enough for expected mobile clock drift and network delay. Each accepted request's replay record is retained until at least `expiresAt` plus the clock-skew allowance.

### Distributed store interface

The server integration exposes one atomic operation equivalent to:

`TryConsumeAsync(scope, requestId, retainUntil, cancellationToken)`

- `scope` is derived from the validated caller identity and API audience, with an unambiguous encoding.
- `requestId` is the validated per-attempt identifier.
- `retainUntil` is no earlier than `expiresAt + clockSkewAllowance`.
- The operation atomically inserts the identifier if absent and returns either `Accepted` or `AlreadySeen`.
- The implementation must be shared by all API instances that can receive the same caller's traffic. A process-local dictionary is not sufficient for a scaled deployment.
- Store keys should be namespaced and should not expose raw credentials. Implementations may hash the composite replay key before storage.
- Expired records may be removed only after their retention deadline.

This abstraction can be backed by Redis, a database with a unique constraint, or another store that provides an atomic insert-if-absent operation with expiry. EnvelopeKit should define the contract, not require one storage vendor.

### Failure and retry behaviour

The API writes the replay record after authentication, decryption, and validation, but before endpoint/business processing. If the identifier is already present, the API rejects the attempt without invoking application processing. If the replay store is unavailable or the atomic operation has an indeterminate result, protected processing fails closed and the endpoint is not invoked.

A process failure after the record is stored but before a response is delivered means that attempt cannot safely be repeated with the same `requestId`. The client creates a new request identifier and a fresh one-use response key for every retry. This provides at-most-once acceptance of a protocol attempt, not exactly-once execution of a business operation.

Applications that must avoid performing a business action twice after a timeout or uncertain outcome must also use their normal business idempotency mechanism. That key is separate from `requestId` and is evaluated by application logic. EnvelopeKit replay protection does not make a non-idempotent business operation exactly once.

The replay store must be written before application processing, so failure between the write and endpoint execution may require the client to submit a new protocol attempt. The application idempotency mechanism is what makes that retry safe for operations that need it.

### Observability and errors

Replay rejections and replay-store failures should be observable through structured, privacy-safe diagnostics. Logs must not include decrypted body data, private keys, access tokens, or raw replay identifiers. The external error mapping must not reveal cryptographic internals. The protocol still needs to settle exact HTTP status and encrypted/plain error behaviour for failures that occur before a response key is trusted.

## 3. Decisions still open

- Final algorithm profile and the corresponding exact JWK parameters.
- Concrete manifest freshness, cache, and clock-skew defaults.
- Whether manifest payload fields use only registered JOSE claim names or a namespaced private schema.
- Root public key configuration API and operational root replacement procedure.
- Concrete maximum request lifetime and retention defaults.
- Exact replay-store .NET interface, cancellation semantics, and failure mapping.
- Whether a response to a duplicate request can be encrypted safely using the supplied one-use response key, and the external status/error format.

Until these points are settled and reviewed across .NET, browser, and mobile runtimes, the schema and behaviour above remain proposals.
