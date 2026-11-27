using System.Text.Json;
using System.Text.Json.Serialization;

namespace EnvelopeKit.Protocol;

/// <summary>
/// Provisional signed-manifest payload. The JWS is verified by the caller before
/// this payload is accepted or used.
/// </summary>
public sealed record EnvelopeKeyManifest
{
    [JsonPropertyName("iss")]
    public required string Issuer { get; init; }

    [JsonPropertyName("aud")]
    public required JsonElement Audience { get; init; }

    [JsonPropertyName("version")]
    public long Version { get; init; }

    [JsonPropertyName("iat")]
    public long IssuedAt { get; init; }

    [JsonPropertyName("exp")]
    public long ExpiresAt { get; init; }

    [JsonPropertyName("keys")]
    public required IReadOnlyList<EnvelopeManifestKey> Keys { get; init; }
}

/// <summary>A public operational key advertised by the provisional manifest schema.</summary>
public sealed record EnvelopeManifestKey
{
    [JsonPropertyName("kid")]
    public required string KeyId { get; init; }

    [JsonPropertyName("use")]
    public required string Use { get; init; }

    [JsonPropertyName("alg")]
    public required string Algorithm { get; init; }

    [JsonPropertyName("nbf")]
    public long NotBefore { get; init; }

    [JsonPropertyName("exp")]
    public long ExpiresAt { get; init; }

    [JsonPropertyName("jwk")]
    public required JsonElement JsonWebKey { get; init; }
}

/// <summary>Validates the provisional manifest payload after its JWS is verified.</summary>
public static class EnvelopeKeyManifestValidator
{
    private static readonly HashSet<string> AllowedJwkProperties =
        new(StringComparer.Ordinal) { "kty", "crv", "x", "y", "kid", "use", "alg", "key_ops" };

    private static readonly HashSet<string> PrivateJwkProperties =
        new(StringComparer.Ordinal) { "d", "p", "q", "dp", "dq", "qi", "oth", "k" };

    /// <summary>
    /// Validates manifest scope, time bounds, version, key identifiers, purposes,
    /// algorithms, and public-only P-256 JWKs.
    /// </summary>
    public static void Validate(
        EnvelopeKeyManifest manifest,
        string expectedIssuer,
        string expectedAudience,
        DateTimeOffset now,
        TimeSpan maximumFreshness,
        TimeSpan clockSkew,
        long? highestAcceptedVersion = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAudience);

        if (maximumFreshness <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumFreshness));
        }

        if (clockSkew < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkew));
        }

        if (!string.Equals(manifest.Issuer, expectedIssuer, StringComparison.Ordinal))
        {
            throw new EnvelopeProtocolException("The manifest issuer does not match the configured API.");
        }

        if (!HasAudience(manifest.Audience, expectedAudience))
        {
            throw new EnvelopeProtocolException("The manifest audience does not include the configured application.");
        }

        if (manifest.Version <= 0 ||
            (highestAcceptedVersion.HasValue && manifest.Version < highestAcceptedVersion.Value))
        {
            throw new EnvelopeProtocolException("The manifest version is invalid or older than the last accepted version.");
        }

        var nowUnix = now.ToUnixTimeSeconds();
        var skewSeconds = (long)Math.Ceiling(clockSkew.TotalSeconds);
        var maximumAgeSeconds = (long)Math.Floor(maximumFreshness.TotalSeconds);

        if (manifest.IssuedAt > nowUnix + skewSeconds ||
            manifest.ExpiresAt <= nowUnix - skewSeconds ||
            manifest.ExpiresAt <= manifest.IssuedAt ||
            manifest.ExpiresAt - manifest.IssuedAt > maximumAgeSeconds ||
            nowUnix - manifest.IssuedAt > maximumAgeSeconds + skewSeconds)
        {
            throw new EnvelopeProtocolException("The manifest is outside its permitted validity window.");
        }

        if (manifest.Keys is null || manifest.Keys.Count == 0)
        {
            throw new EnvelopeProtocolException("The manifest does not contain any operational keys.");
        }

        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        var hasEncryptionKey = false;
        var hasSigningKey = false;

        foreach (var key in manifest.Keys)
        {
            ValidateKey(key, manifest.ExpiresAt);

            if (!identifiers.Add(key.KeyId))
            {
                throw new EnvelopeProtocolException("The manifest contains a duplicate key identifier.");
            }

            hasEncryptionKey |= key.Use == "enc";
            hasSigningKey |= key.Use == "sig";
        }

        if (!hasEncryptionKey || !hasSigningKey)
        {
            throw new EnvelopeProtocolException("The manifest must include encryption and response-verification keys.");
        }
    }

    private static void ValidateKey(EnvelopeManifestKey key, long manifestExpiry)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (string.IsNullOrWhiteSpace(key.KeyId) || key.KeyId.Length > 128)
        {
            throw new EnvelopeProtocolException("The manifest contains an invalid key identifier.");
        }

        if (key.NotBefore >= key.ExpiresAt ||
            key.ExpiresAt > manifestExpiry ||
            (key.Use != "enc" && key.Use != "sig"))
        {
            throw new EnvelopeProtocolException("The manifest contains an invalid key validity interval or purpose.");
        }

        var expectedAlgorithm = key.Use switch
        {
            "enc" => "ECDH-ES",
            "sig" => "ES256",
            _ => throw new EnvelopeProtocolException("The manifest contains an unsupported key purpose.")
        };

        if (!string.Equals(key.Algorithm, expectedAlgorithm, StringComparison.Ordinal))
        {
            throw new EnvelopeProtocolException("The manifest key algorithm does not match its purpose.");
        }

        ValidatePublicJwk(key.JsonWebKey, key, expectedAlgorithm);
    }

    private static void ValidatePublicJwk(
        JsonElement jwk,
        EnvelopeManifestKey key,
        string expectedAlgorithm)
    {
        if (jwk.ValueKind != JsonValueKind.Object)
        {
            throw new EnvelopeProtocolException("The manifest key is not a JWK object.");
        }

        var propertyNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in jwk.EnumerateObject())
        {
            if (!propertyNames.Add(property.Name))
            {
                throw new EnvelopeProtocolException("The JWK contains a duplicate property.");
            }

            if (PrivateJwkProperties.Contains(property.Name) ||
                !AllowedJwkProperties.Contains(property.Name))
            {
                throw new EnvelopeProtocolException("The JWK contains private or unsupported key material.");
            }
        }

        if (ReadString(jwk, "kty") != "EC" ||
            ReadString(jwk, "crv") != "P-256" ||
            ReadString(jwk, "kid") != key.KeyId ||
            ReadString(jwk, "use") != key.Use ||
            ReadString(jwk, "alg") != expectedAlgorithm)
        {
            throw new EnvelopeProtocolException("The JWK does not match the manifest key metadata.");
        }

        ValidateCoordinate(ReadString(jwk, "x"));
        ValidateCoordinate(ReadString(jwk, "y"));

        if (jwk.TryGetProperty("key_ops", out var operations))
        {
            var expectedOperation = key.Use == "enc" ? "deriveKey" : "verify";
            if (operations.ValueKind != JsonValueKind.Array ||
                operations.GetArrayLength() != 1 ||
                operations[0].ValueKind != JsonValueKind.String ||
                operations[0].GetString() != expectedOperation)
            {
                throw new EnvelopeProtocolException("The JWK key_ops value is not permitted by this profile.");
            }
        }
    }

    private static bool HasAudience(JsonElement audience, string expectedAudience)
    {
        if (audience.ValueKind == JsonValueKind.String)
        {
            return string.Equals(audience.GetString(), expectedAudience, StringComparison.Ordinal);
        }

        if (audience.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var value in audience.EnumerateArray())
        {
            if (value.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            if (string.Equals(value.GetString(), expectedAudience, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static string ReadString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            throw new EnvelopeProtocolException($"The JWK is missing its {propertyName} string.");
        }

        return value.GetString()
            ?? throw new EnvelopeProtocolException($"The JWK contains an invalid {propertyName} value.");
    }

    private static void ValidateCoordinate(string coordinate)
    {
        if (coordinate.Length == 0 ||
            coordinate.Any(character =>
                !(character is >= 'A' and <= 'Z' or
                  >= 'a' and <= 'z' or
                  >= '0' and <= '9' or '-' or '_')))
        {
            throw new EnvelopeProtocolException("The JWK contains an invalid base64url coordinate.");
        }

        var padded = coordinate.Replace('-', '+').Replace('_', '/');
        padded = padded.Length % 4 switch
        {
            0 => padded,
            2 => padded + "==",
            3 => padded + "=",
            _ => throw new EnvelopeProtocolException("The JWK contains an invalid base64url coordinate.")
        };

        try
        {
            if (Convert.FromBase64String(padded).Length != 32)
            {
                throw new EnvelopeProtocolException("The JWK coordinate is not the expected P-256 length.");
            }
        }
        catch (FormatException exception)
        {
            throw new EnvelopeProtocolException("The JWK contains an invalid base64url coordinate.", exception);
        }
    }
}
