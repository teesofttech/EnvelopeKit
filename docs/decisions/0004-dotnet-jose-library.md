# ADR 0004: .NET JOSE implementation candidate

- Status: Provisional selection for the first .NET implementation
- Decision: Use `jose-jwt` 5.3.0 behind an EnvelopeKit-owned internal JOSE adapter for the .NET 10 SDK prototype and first implementation increment. Keep the dependency out of public EnvelopeKit API signatures. This is not a production-readiness decision; release remains blocked on protocol stabilisation, cross-platform interoperability, dependency review, and security review.
- Scope: This decision concerns the .NET JOSE implementation only. It does not choose browser or mobile libraries.

## Context

The candidate EnvelopeKit profile is compact JWE with ECDH-ES/A256GCM using P-256, and compact JWS with ES256 for signed API responses. The existing cross-runtime prototype passed with `jose-jwt` 5.3.0 on .NET and `jose` 6.2.16 in JavaScript, including an actual Chromium run in CI. The profile itself remains provisional.

The production implementation must use maintained JOSE functionality rather than hand-implementing JWS, JWE, ECDH-ES, AES-GCM, or JOSE serialization. It must enforce a fixed algorithm profile regardless of algorithms offered by a received message.

## Options considered

| Option | Assessment |
| --- | --- |
| `jose-jwt` 5.3.0 | Supports the prototype's ECDH-ES/A256GCM and ES256 candidate, JWK, and .NET 6 or higher. Its own documentation describes cross-platform ECDH support and APIs for removing unused algorithms. It is the only option evaluated here that has already passed EnvelopeKit's .NET-to-JavaScript prototype. Its broad JOSE support requires EnvelopeKit to enforce a narrow allow-list and strict key-purpose separation. |
| Microsoft.IdentityModel | Familiar in ASP.NET Core and supports several JOSE operations. The current issue tracker records unresolved implementation problems affecting ECDH-ES and ECDH-ES+A*KW combinations. It is not selected as the JWE provider for the current candidate profile. Reassess if a future release resolves the needed profile and passes the same interoperability checks. |
| Implement JOSE using .NET cryptography APIs | Avoids an external JOSE dependency but would require EnvelopeKit to implement and maintain JOSE serialization, key derivation, JWS/JWE validation, and edge-case handling. Rejected because this increases cryptographic implementation risk. |

## Required integration constraints

1. Wrap `jose-jwt` behind an internal interface so EnvelopeKit can replace it without changing its public API.
2. Pin the package version centrally and review each update before adoption.
3. Configure only the profile's required operations. Reject `none`, compression, alternate key management, alternate content encryption, and alternate signature algorithms unless a later reviewed profile explicitly permits them.
4. Validate the protected header and expected key identifier and purpose before processing. Do not let received header values select arbitrary keys or algorithms.
5. Keep request-encryption keys, response-signing keys, and one-use client response keys separate by purpose.
6. Use the library's dedicated verification and decryption operations and strict validation APIs where available. Do not treat decoding without verification as authenticated data.
7. Keep key import, manifest parsing, and protocol validation in EnvelopeKit-owned code with explicit bounds and validation.
8. Run the existing .NET, JavaScript, and Chromium interoperability scenarios against the adapter before changing the provisional profile. Add mobile checks before claiming mobile support.
9. Review package provenance, licence, advisories, and transitive dependency changes before the first public package release.

## Consequences

The existing .NET interoperability prototype can be reused as the first adapter implementation. The dependency remains an internal implementation detail. The SDK can begin with this provider while its protocol types remain provisional, but no package should claim production security or stable wire compatibility until the release conditions above are met.

The library supports a broad algorithm surface, including algorithms EnvelopeKit must not accept. It must be configured and wrapped so protocol code accepts only the fixed, reviewed profile. Library capability does not imply protocol permission.

## References

- `jose-jwt` project and supported algorithms: https://github.com/dvsekhvalnov/jose-jwt
- `jose-jwt` 5.3.0 package and target frameworks: https://www.nuget.org/packages/jose-jwt/5.3.0
- `jose-jwt` 5.3.0 release notes: https://github.com/dvsekhvalnov/jose-jwt/releases/tag/v5.3.0
- Microsoft IdentityModel issue #3654: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/3654
- Microsoft IdentityModel issue #3653: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/3653
