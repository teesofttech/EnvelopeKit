# Architecture overview

EnvelopeKit is planned as a language-neutral HTTP payload protocol with a .NET-first implementation.

- `EnvelopeKit.Protocol` will hold .NET protocol models and validation rules.
- `EnvelopeKit.Http` will provide client-side HTTP integration.
- `EnvelopeKit.AspNetCore` will provide server-side integration.
- The API application must authenticate and authorise callers separately from payload encryption.
- Key discovery, response-origin authentication and replay protection are part of the end-to-end design, not solved by encryption alone.

The current projects are empty scaffolds apart from the sample API health endpoint. No cryptographic scheme, envelope fields, key discovery mechanism, replay store contract or middleware behaviour has been selected. See the [working threat model](../security/threat-model.md) and [cryptographic profile ADR](../decisions/0002-cryptographic-profile.md) for the current proposals.
