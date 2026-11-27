# EnvelopeKit threat model

**Status: working draft, threat assumptions agreed on 27 November 2026.** The design includes an active gateway that may alter traffic and key discovery. API responses must be signed before encryption in the first version. This is not a protocol specification and the current scaffold does not protect traffic.

## Security objective

EnvelopeKit should let an application encrypt selected JSON HTTP request and response bodies from the client application to the API application, so forwarding infrastructure between those endpoints cannot read the body. It should detect changes to encrypted content and reject duplicate requests within a defined replay window.

HTTPS remains required. EnvelopeKit supplements transport security across deployments where TLS terminates before the API process.

## Assets

- Plaintext JSON request and response bodies.
- API encryption private keys and client per-request response private keys.
- API response-signing private keys, if response origin authentication is adopted.
- Replay identifiers and state.
- The association between a response and the request that caused it.

## Trust boundaries and actors

| Actor | Assumed capability |
| --- | --- |
| Client application | Holds and processes request and response plaintext. The SDK can access plaintext in memory. |
| API application | Decrypts requests and creates plaintext responses. It is trusted with both. |
| Forwarding infrastructure | May observe, log, copy, delay, replay, drop, reorder or modify HTTP traffic. Its TLS termination point may be able to read ordinary HTTP bodies. |
| Network attacker | May observe or alter traffic outside trusted TLS segments. |
| Caller | May be unauthenticated, authenticated, or malicious while using valid credentials. |

The primary design target is a curious or active forwarding intermediary. The API and client endpoints, their operating systems, and their application code are trusted. A compromised API or client can read plaintext and is outside the protection boundary.

## Proposed protections

| Threat | Intended control | Limit |
| --- | --- | --- |
| Gateway reads a selected body | Encrypt the body to an authenticated API public key; encrypt the response to a per-request client public key | URLs, methods, headers, status, timing, and approximate body size remain visible |
| Encrypted body is modified | Authenticated encryption; reject on authentication-tag failure | This detects alteration, but does not identify who created a valid ciphertext |
| Captured request is replayed | Authenticated request identifier and expiry, plus an atomic shared replay store | A timestamp alone is insufficient. The replay window and storage semantics must be specified |
| Old response is substituted | Bind response to request correlation data; authenticate the API response origin | Encryption to a public client key alone does not prove who encrypted the response |
| Public key is substituted | Authenticate key discovery with a trust anchor that the intermediary cannot replace | HTTPS to a gateway that terminates TLS does not, by itself, protect key discovery from that gateway |
| Client tries to access another caller's data | Existing API authentication and authorisation, enforced by the API | Payload encryption is not caller authentication or access control |
| Algorithm downgrade or confusion | One explicitly configured protocol profile and strict algorithm allow-lists | Do not select algorithms based only on untrusted envelope fields |

## Important distinctions

### Encryption is not caller authentication

Anyone who has the API's public encryption key can create a ciphertext the API can decrypt. The API must authenticate and authorise the caller independently. Existing bearer tokens and other HTTP headers remain outside the encrypted body unless an application separately protects them.

### Authenticated encryption is not sender authentication

An AEAD tag proves that ciphertext and authenticated metadata were not changed after creation. It does not prove which client created a public-key-encrypted request. Similarly, anyone can encrypt data to a client's public response key. If the API must be verifiable even when a gateway can alter responses, the client needs to verify an API signature whose public key is trusted independently.

### Key discovery is part of the security boundary

If the SDK fetches the API public key from a key-set URL and a gateway can replace that response, the gateway can direct the SDK to encrypt to an attacker key. Key discovery therefore needs a trust anchor that survives TLS termination. The current proposal is a signed key manifest verified against a root public key configured by the application developer. The root must not be learned solely from the same untrusted key endpoint. Rotation and recovery must preserve that trust anchor. See the [key discovery proposal](../decisions/0003-key-discovery.md).

## Proposed request and response shape

This is a design sketch, not a format decision.

1. The client authenticates the API public encryption key using the configured trust method.
2. For each request, the client creates a fresh response key pair and encrypts an inner envelope containing the JSON body, response public key, request identifier, expiry, and request context.
3. The client sends the encrypted envelope over HTTPS. The API authenticates and authorises the caller, decrypts the body, validates request context and expiry, and atomically records the request identifier before application processing.
4. The API signs the application result with its response-signing key, then encrypts it to the one-use response public key. Both operations are required in the first version.
5. The client decrypts the response, verifies the API signature and request correlation, then returns ordinary JSON to the calling application.

The API must validate that protected request context matches the actual HTTP method and target. Do not trust routing or authorization claims merely because they appear in an encrypted body.

## Replay and retry semantics

Replay protection needs a shared, atomic store for horizontally scaled APIs. The store should record a request identifier scoped to the authenticated caller and retain it through the accepted expiry window. A request identifier must be unpredictable and unique per attempt.

Anti-replay identifiers and business idempotency keys solve different problems. A client retry should create a new encrypted request identifier. If the operation must not run twice, the application should also use its normal idempotency mechanism. The protocol must define what happens when the replay record is written but application processing fails.

## Out of scope for the initial design

- Hiding HTTP metadata, traffic patterns, or body length.
- Protecting plaintext on a compromised or jailbroken device, or from XSS and malicious browser extensions.
- Protecting a browser SDK when the same untrusted gateway can replace the web application's JavaScript. Modified JavaScript can read plaintext before encryption or expose it after decryption. Web support can claim protection from a gateway only when the application code and its configured trust root are delivered through a separately trusted path.
- Protecting data from the API or its operators after decryption.
- Replacing TLS, OAuth/OIDC, API authentication, authorisation, CSRF controls, input validation, rate limiting, or application idempotency.
- Preventing denial of service, traffic blocking, or business-logic abuse.
- Encrypting arbitrary streaming, multipart, or file uploads until separately designed.

## Questions to settle before implementation

1. Is the infrastructure threat model a gateway that may actively alter key discovery and HTTP responses, or only one that can read and replay traffic?
2. Should API response signatures be mandatory in the first version?
3. How should SDK users anchor and rotate API encryption and response-verification keys?
4. Which replay-store interface and failure policy should middleware expose?
5. Which HTTP bodies and routes are eligible for protection, and how should errors be represented?
