# Architecture overview

EnvelopeKit is planned as a language-neutral HTTP payload protocol with a .NET-first implementation.

- `EnvelopeKit.Protocol` will hold protocol models and validation rules.
- `EnvelopeKit.Http` will provide client-side HTTP integration.
- `EnvelopeKit.AspNetCore` will provide server-side integration.
- JWE is the selected message-encryption format. The exact serialisation and algorithm profile remain open pending cross-platform interoperability checks.
- API responses must be signed before encryption in the first version.
- The accepted key trust model uses an application-configured root public key and a signed, rotating API key manifest.
- API authentication, authorisation, key rotation, response-origin authentication and replay protection remain distinct parts of the design.
- A browser SDK cannot protect plaintext from a gateway that can replace the JavaScript application itself.

The current projects are empty scaffolds apart from the sample API health endpoint. No encryption, signing, key manifest, or replay middleware is implemented. See the [working threat model](../security/threat-model.md), [cryptographic profile ADR](../decisions/0002-cryptographic-profile.md), [key discovery ADR](../decisions/0003-key-discovery.md), and [protocol design draft](protocol-design.md).
