using System.Security.Cryptography;
using System.Text.Json;

namespace EnvelopeKit.Cryptography;

/// <summary>
/// Imports and exports the provisional EnvelopeKit P-256 JWK profile.
/// Private-key exports contain sensitive material and must be stored securely.
/// </summary>
public static class EnvelopeJwkKeyConverter
{
    private const int MaximumJwkLength = 4096;
    private const string P256CurveOid = "1.2.840.10045.3.1.7";
    private static readonly HashSet<string> PublicProperties =
        new(StringComparer.Ordinal) { "kty", "crv", "x", "y", "kid", "use", "alg" };

    /// <summary>Exports a public ECDH key as a public-only encryption JWK.</summary>
    public static string ExportPublicEcdh(ECDiffieHellman key, string keyId)
    {
        ArgumentNullException.ThrowIfNull(key);
        ValidateKeyId(keyId);
        EnsureP256(key);

        var parameters = key.ExportParameters(includePrivateParameters: false);
        return SerializeJwk(parameters, keyId, "enc", "ECDH-ES", includePrivate: false);
    }

    /// <summary>
    /// Exports an ECDH key as a private encryption JWK.
    /// The returned string contains private key material.
    /// </summary>
    public static string ExportPrivateEcdh(ECDiffieHellman key, string keyId)
    {
        ArgumentNullException.ThrowIfNull(key);
        ValidateKeyId(keyId);
        EnsureP256(key);

        var parameters = key.ExportParameters(includePrivateParameters: true);
        try
        {
            return SerializeJwk(parameters, keyId, "enc", "ECDH-ES", includePrivate: true);
        }
        finally
        {
            if (parameters.D is not null)
            {
                CryptographicOperations.ZeroMemory(parameters.D);
            }
        }
    }

    /// <summary>Exports a public ECDSA key as a response-verification JWK.</summary>
    public static string ExportPublicEcdsa(ECDsa key, string keyId)
    {
        ArgumentNullException.ThrowIfNull(key);
        ValidateKeyId(keyId);
        EnsureP256(key);

        var parameters = key.ExportParameters(includePrivateParameters: false);
        return SerializeJwk(parameters, keyId, "sig", "ES256", includePrivate: false);
    }

    /// <summary>
    /// Exports an ECDSA key as a private response-signing JWK.
    /// The returned string contains private key material.
    /// </summary>
    public static string ExportPrivateEcdsa(ECDsa key, string keyId)
    {
        ArgumentNullException.ThrowIfNull(key);
        ValidateKeyId(keyId);
        EnsureP256(key);

        var parameters = key.ExportParameters(includePrivateParameters: true);
        try
        {
            return SerializeJwk(parameters, keyId, "sig", "ES256", includePrivate: true);
        }
        finally
        {
            if (parameters.D is not null)
            {
                CryptographicOperations.ZeroMemory(parameters.D);
            }
        }
    }

    /// <summary>Imports a public P-256 ECDH encryption JWK.</summary>
    public static ECDiffieHellman ImportPublicEcdh(string jwk, string expectedKeyId)
    {
        var parsed = Parse(jwk, expectedKeyId, "enc", "ECDH-ES", requirePrivate: false);
        return ECDiffieHellman.Create(parsed.Parameters);
    }

    /// <summary>Imports a private P-256 ECDH decryption JWK.</summary>
    public static ECDiffieHellman ImportPrivateEcdh(string jwk, string expectedKeyId)
    {
        var parsed = Parse(jwk, expectedKeyId, "enc", "ECDH-ES", requirePrivate: true);
        try
        {
            return ECDiffieHellman.Create(parsed.Parameters);
        }
        finally
        {
            if (parsed.Parameters.D is not null)
            {
                CryptographicOperations.ZeroMemory(parsed.Parameters.D);
            }
        }
    }

    /// <summary>Imports a public P-256 ECDSA response-verification JWK.</summary>
    public static ECDsa ImportPublicEcdsa(string jwk, string expectedKeyId)
    {
        var parsed = Parse(jwk, expectedKeyId, "sig", "ES256", requirePrivate: false);
        return ECDsa.Create(parsed.Parameters);
    }

    /// <summary>Imports a private P-256 ECDSA response-signing JWK.</summary>
    public static ECDsa ImportPrivateEcdsa(string jwk, string expectedKeyId)
    {
        var parsed = Parse(jwk, expectedKeyId, "sig", "ES256", requirePrivate: true);
        try
        {
            return ECDsa.Create(parsed.Parameters);
        }
        finally
        {
            if (parsed.Parameters.D is not null)
            {
                CryptographicOperations.ZeroMemory(parsed.Parameters.D);
            }
        }
    }

    private static string SerializeJwk(
        ECParameters parameters,
        string keyId,
        string use,
        string algorithm,
        bool includePrivate)
    {
        var jwk = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncode(parameters.Q.X!),
            ["y"] = Base64UrlEncode(parameters.Q.Y!),
            ["kid"] = keyId,
            ["use"] = use,
            ["alg"] = algorithm
        };

        if (includePrivate)
        {
            jwk["d"] = Base64UrlEncode(parameters.D
                ?? throw new CryptographicException("The key does not contain private key material."));
        }

        return JsonSerializer.Serialize(jwk);
    }

    private static ParsedKey Parse(
        string jwk,
        string expectedKeyId,
        string expectedUse,
        string expectedAlgorithm,
        bool requirePrivate)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jwk);
        ValidateKeyId(expectedKeyId);

        if (jwk.Length > MaximumJwkLength)
        {
            throw new ArgumentOutOfRangeException(nameof(jwk), "The JWK exceeds the maximum supported length.");
        }

        using var document = JsonDocument.Parse(jwk);
        var root = document.RootElement;

        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new CryptographicException("The JWK must be a JSON object.");
        }

        var properties = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!properties.Add(property.Name))
            {
                throw new CryptographicException("The JWK contains a duplicate property.");
            }

            if (!PublicProperties.Contains(property.Name) &&
                !(requirePrivate && property.Name == "d"))
            {
                throw new CryptographicException("The JWK contains an unsupported property.");
            }
        }

        if (ReadString(root, "kty") != "EC" ||
            ReadString(root, "crv") != "P-256" ||
            ReadString(root, "kid") != expectedKeyId ||
            ReadString(root, "use") != expectedUse ||
            ReadString(root, "alg") != expectedAlgorithm)
        {
            throw new CryptographicException("The JWK does not match the expected key, purpose, or algorithm.");
        }

        var x = Base64UrlDecode(ReadString(root, "x"));
        var y = Base64UrlDecode(ReadString(root, "y"));
        byte[]? d = null;

        if (x.Length != 32 || y.Length != 32)
        {
            throw new CryptographicException("The JWK does not contain valid P-256 coordinates.");
        }

        if (requirePrivate)
        {
            d = Base64UrlDecode(ReadString(root, "d"));
            if (d.Length != 32)
            {
                CryptographicOperations.ZeroMemory(d);
                throw new CryptographicException("The JWK does not contain a valid P-256 private value.");
            }
        }
        else if (root.TryGetProperty("d", out _))
        {
            throw new CryptographicException("A public JWK must not contain private key material.");
        }

        return new ParsedKey(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
            D = d
        });
    }

    private static string ReadString(JsonElement objectElement, string propertyName)
    {
        if (!objectElement.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            throw new CryptographicException($"The JWK is missing its {propertyName} string.");
        }

        return value.GetString()
            ?? throw new CryptographicException($"The JWK contains an invalid {propertyName} value.");
    }

    private static byte[] Base64UrlDecode(string value)
    {
        if (string.IsNullOrEmpty(value) ||
            value.Any(character =>
                !(character is >= 'A' and <= 'Z' or
                  >= 'a' and <= 'z' or
                  >= '0' and <= '9' or '-' or '_')))
        {
            throw new CryptographicException("The JWK contains invalid base64url data.");
        }

        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            0 => padded,
            2 => padded + "==",
            3 => padded + "=",
            _ => throw new CryptographicException("The JWK contains invalid base64url data.")
        };

        try
        {
            return Convert.FromBase64String(padded);
        }
        catch (FormatException exception)
        {
            throw new CryptographicException("The JWK contains invalid base64url data.", exception);
        }
    }

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

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
        if (key.KeySize != 256 ||
            key.ExportParameters(includePrivateParameters: false).Curve.Oid.Value != P256CurveOid)
        {
            throw new ArgumentException("The provisional profile requires a P-256 ECDH key.", nameof(key));
        }
    }

    private static void EnsureP256(ECDsa key)
    {
        if (key.KeySize != 256 ||
            key.ExportParameters(includePrivateParameters: false).Curve.Oid.Value != P256CurveOid)
        {
            throw new ArgumentException("The provisional profile requires a P-256 ECDSA key.", nameof(key));
        }
    }

    private sealed record ParsedKey(ECParameters Parameters);
}
