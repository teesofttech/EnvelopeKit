using System.Security.Cryptography;
using EnvelopeKit.Protocol;

namespace EnvelopeKit.Cryptography;

/// <summary>
/// Creates the compact JWS published by an API as its signed key manifest.
/// Sign manifests offline where practical, then serve the resulting JWS as
/// static content so the root private key does not need to be online.
/// </summary>
public sealed class EnvelopeKeyManifestSigner
{
    public const string ManifestJwsType = "application/envelopekit-key-manifest+jws";

    private readonly JosePayloadCryptography _cryptography;

    public EnvelopeKeyManifestSigner(JosePayloadCryptography? cryptography = null)
    {
        _cryptography = cryptography ?? new JosePayloadCryptography();
    }

    /// <summary>Serialises a manifest and signs it with the configured P-256 root key.</summary>
    public string Sign(
        EnvelopeKeyManifest manifest,
        ECDsa rootSigningKey,
        string rootKeyId)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(rootSigningKey);

        var payload = EnvelopeProtocolJson.Serialize(manifest);
        return _cryptography.SignCompactJws(
            payload,
            rootSigningKey,
            rootKeyId,
            ManifestJwsType);
    }
}
