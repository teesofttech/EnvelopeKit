# ADR 0002: Cryptographic profile

- Status: Proposed, decision deferred
- Decision: None yet.
- Context: The protocol must be interoperable across .NET, browser and mobile clients. Selecting a cryptographic profile requires a threat model and a documented comparison of established standards.
- Consequences: No encryption, key agreement, envelope format or wire-level behaviour will be implemented until this decision is reviewed and accepted.

The project will not define custom cryptographic primitives.
