# Architecture overview

EnvelopeKit is planned as a language-neutral HTTP payload protocol with a .NET-first implementation.

- `EnvelopeKit.Protocol` will hold .NET protocol models and validation rules.
- `EnvelopeKit.Http` will provide client-side HTTP integration.
- `EnvelopeKit.AspNetCore` will provide server-side integration.
- The API application must authenticate and authorise callers separately from payload encryption.
- API responses must be signed before encryption in the first version.
- Key discovery, key rotation, response-origin authentication and replay protection are part of the end-to-end design, not solved by encryption alone.
- A browser SDK cannot protect plaintext from a gateway that can replace the JavaScript application itself.

The current projects are empty scaffolds apart from the sample API health endpoint. No cryptographic scheme, envelope fields, key discovery mechanism, replay store contract or middleware behaviour has been selected. See the [working threat model](../security/threat-model.md), [cryptographic profile ADR](../decisions/0002-cryptographic-profile.md), and [key discovery ADR](../decisions/0003-key-discovery.md) for the current proposals.
