# Architecture overview

EnvelopeKit is planned as a language-neutral HTTP payload protocol with a .NET-first implementation.

- `EnvelopeKit.Protocol` will hold .NET protocol models and validation rules.
- `EnvelopeKit.Http` will provide client-side HTTP integration.
- `EnvelopeKit.AspNetCore` will provide server-side integration.
- The API application must authenticate and authorise callers separately from payload encryption.

The current projects are empty scaffolds apart from the sample API health endpoint. No cryptographic scheme, envelope fields, key discovery mechanism, replay store contract or middleware behaviour has been selected.
