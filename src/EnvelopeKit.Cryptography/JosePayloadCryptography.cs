using System.Security.Cryptography;
using Jose;

namespace EnvelopeKit.Cryptography;

/// <summary>
/// Provides the compact JOSE operations used by the provisional EnvelopeKit profile.
/// The public API deliberately exposes only ECDH-ES/A256GCM and ES256.
/// </summary>
/// <remarks>
/// This low-level provider does not validate EnvelopeKit envelopes, key manifests,
/// timestamps, replay state, or HTTP request context. Those checks belong to the
/// protocol and server/client integrations.
/// </remarks>
public sealed class JosePayloadCryptography
{
    private static readonly HashSet<string> JweHeaders =
        new(StringComparer.Ordinal) { "alg", "enc", "epk", "kid" };

    private static readonly HashSet<string> JwsHeaders =
        new(StringComparer.Ordinal) { "alg", "kid" };

    /// <summary>
    /// Encrypts bytes as a compact JWE for a P-256 recipient key.
    /// </summary>
    public string EncryptCompactJwe(
        ReadOnlySpan<byte> plaintext,
        ECDiffieHellman recipientPublicKey,
        string keyId)
    {
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ValidateKeyId(keyId);
        EnsureP256(recipientPublicKey);

        var headers = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["kid"] = keyId
        };

        return JWT.EncodeBytes(
            plaintext.ToArray(),
            recipientPublicKey,
            JweAlgorithm.ECDH_ES,
            JweEncryption.A256GCM,
            compression: null,
            extraHeaders: headers,
            settings: CreateRestrictedSettings());
    }

    /// <summary>
    /// Decrypts a compact JWE only when its protected header matches this profile
    /// and the expected encryption key identifier.
    /// </summary>
    public byte[] DecryptCompactJwe(
        string compactJwe,
        ECDiffieHellman recipientPrivateKey,
        string expectedKeyId)
    {
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ValidateKeyId(expectedKeyId);
        EnsureP256(recipientPrivateKey);
        ValidateCompactToken(compactJwe, expectedSegments: 5);
        ValidateProtectedHeaders(compactJwe, JweHeaders, expectedKeyId, "ECDH-ES", "A256GCM");

        return JWT.DecryptBytes(
            compactJwe,
            recipientPrivateKey,
            JweAlgorithm.ECDH_ES,
            JweEncryption.A256GCM,
            settings: CreateRestrictedSettings());
    }

    /// <summary>
    /// Signs bytes as a compact JWS using ES256 and a P-256 signing key.
    /// </summary>
    public string SignCompactJws(
        ReadOnlySpan<byte> payload,
        ECDsa signingPrivateKey,
        string keyId)
    {
        ArgumentNullException.ThrowIfNull(signingPrivateKey);
        ValidateKeyId(keyId);
        EnsureP256(signingPrivateKey);

        var headers = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["kid"] = keyId
        };

        return JWT.EncodeBytes(
            payload.ToArray(),
            signingPrivateKey,
            JwsAlgorithm.ES256,
            extraHeaders: headers,
            settings: CreateRestrictedSettings());
    }

    /// <summary>
    /// Verifies a compact JWS using ES256 and the expected P-256 verification key.
    /// </summary>
    public byte[] VerifyCompactJws(
        string compactJws,
        ECDsa signingPublicKey,
        string expectedKeyId)
    {
        ArgumentNullException.ThrowIfNull(signingPublicKey);
        ValidateKeyId(expectedKeyId);
        EnsureP256(signingPublicKey);
        ValidateCompactToken(compactJws, expectedSegments: 3);
        ValidateProtectedHeaders(compactJws, JwsHeaders, expectedKeyId, "ES256");

        return JWT.VerifyBytes(
            compactJws,
            signingPublicKey,
            JwsAlgorithm.ES256,
            settings: CreateRestrictedSettings());
    }

    private static JwtSettings CreateRestrictedSettings()
    {
        var settings = new JwtSettings();

        foreach (var algorithm in Enum.GetValues<JwsAlgorithm>())
        {
            if (algorithm != JwsAlgorithm.ES256)
            {
                settings.DeregisterJws(algorithm);
            }
        }

        foreach (var algorithm in Enum.GetValues<JweAlgorithm>())
        {
            if (algorithm != JweAlgorithm.ECDH_ES)
            {
                settings.DeregisterJwa(algorithm);
            }
        }

        foreach (var algorithm in Enum.GetValues<JweEncryption>())
        {
            if (algorithm != JweEncryption.A256GCM)
            {
                settings.DeregisterJwe(algorithm);
            }
        }

        settings.DeregisterCompression(JweCompression.DEF);
        return settings;
    }

    private static void ValidateProtectedHeaders(
        string compactToken,
        HashSet<string> allowedHeaders,
        string expectedKeyId,
        string expectedAlgorithm,
        string? expectedEncryption = null)
    {
        var headers = JWT.Headers(compactToken, CreateRestrictedSettings());

        if (headers.Keys.Any(header => !allowedHeaders.Contains(header)))
        {
            throw new CryptographicException("The JOSE protected header contains an unsupported parameter.");
        }

        if (!headers.TryGetValue("kid", out var keyId) ||
            !string.Equals(keyId as string, expectedKeyId, StringComparison.Ordinal))
        {
            throw new CryptographicException("The JOSE key identifier does not match the expected key.");
        }

        if (!headers.TryGetValue("alg", out var algorithm) ||
            !string.Equals(algorithm as string, expectedAlgorithm, StringComparison.Ordinal))
        {
            throw new CryptographicException("The JOSE algorithm does not match the configured profile.");
        }

        if (expectedEncryption is not null &&
            (!headers.TryGetValue("enc", out var encryption) ||
             !string.Equals(encryption as string, expectedEncryption, StringComparison.Ordinal)))
        {
            throw new CryptographicException("The JWE content-encryption algorithm does not match the configured profile.");
        }

        if (expectedEncryption is not null && !headers.ContainsKey("epk"))
        {
            throw new CryptographicException("The JWE protected header is missing its ephemeral public key.");
        }
    }

    private static void ValidateCompactToken(string token, int expectedSegments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        if (token.Count(character => character == '.') != expectedSegments - 1)
        {
            throw new CryptographicException("The JOSE value is not in the expected compact serialization.");
        }
    }

    private static void ValidateKeyId(string keyId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);

        if (keyId.Length > 128)
        {
            throw new ArgumentOutOfRangeException(nameof(keyId), "A key identifier cannot exceed 128 characters.");
        }
    }

    private static void EnsureP256(ECDiffieHellman key)
    {
        var curveOid = key.ExportParameters(includePrivateParameters: false).Curve.Oid.Value;

        if (key.KeySize != 256 || curveOid != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            throw new ArgumentException("The provisional JOSE profile requires a P-256 ECDH key.", nameof(key));
        }
    }

    private static void EnsureP256(ECDsa key)
    {
        var curveOid = key.ExportParameters(includePrivateParameters: false).Curve.Oid.Value;

        if (key.KeySize != 256 || curveOid != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            throw new ArgumentException("The provisional JOSE profile requires a P-256 ECDSA key.", nameof(key));
        }
    }
}
