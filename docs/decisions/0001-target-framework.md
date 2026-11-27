# ADR 0001: Initial .NET target

- Status: Accepted
- Decision: Target .NET 10.0 for the first implementation.
- Context: The project is beginning in November 2026 and should start on an actively supported LTS release.
- Consequences: Packages and samples target `net10.0`. Multi-targeting can be considered after compatibility requirements are known.

This decision concerns the framework target only. It does not select cryptographic libraries or protocol behaviour.
