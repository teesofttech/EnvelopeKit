using System.Security.Cryptography;

namespace EnvelopeKit.Cryptography;

/// <summary>
/// Generates P-256 keys for the provisional EnvelopeKit profile.
/// Callers are responsible for storing private keys in an appropriate protected
/// store and disposing the returned key handles.
/// </summary>
public static class EnvelopeP256KeyGenerator
{
    /// <summary>Creates an offline root key for signing key manifests.</summary>
    public static ECDsa CreateManifestRootSigningKey() =>
        ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>Creates an API response-signing key.</summary>
    public static ECDsa CreateApiResponseSigningKey() =>
        ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>Creates an API request-decryption key.</summary>
    public static ECDiffieHellman CreateApiRequestDecryptionKey() =>
        ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>Creates a one-use client response-decryption key.</summary>
    public static ECDiffieHellman CreateClientResponseDecryptionKey() =>
        ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
}
