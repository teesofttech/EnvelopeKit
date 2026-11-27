using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using EnvelopeKit.Cryptography;
using EnvelopeKit.Protocol;

namespace EnvelopeKit.Http;

/// <summary>Configuration for fetching and validating an API key manifest.</summary>
public sealed class EnvelopeKeyManifestClientOptions
{
    public required Uri ManifestUri { get; init; }
    public required string ExpectedIssuer { get; init; }
    public required string ExpectedAudience { get; init; }
    public required string TrustedRootKeyId { get; init; }
    public required string TrustedRootPublicJwk { get; init; }
    public required TimeSpan MaximumFreshness { get; init; }
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Retrieves an API's compact-JWS key manifest, verifies its signature against
/// the configured root key, and validates its scope and public operational keys.
/// </summary>
public sealed class EnvelopeKeyManifestClient
{
    private const int MaximumManifestBytes = 64 * 1024;
    private const string ManifestMediaType = "application/jose";
    private const string ManifestJwsType = "application/envelopekit-key-manifest+jws";

    private readonly HttpClient _httpClient;
    private readonly EnvelopeKeyManifestClientOptions _options;
    private readonly JosePayloadCryptography _cryptography;

    public EnvelopeKeyManifestClient(
        HttpClient httpClient,
        EnvelopeKeyManifestClientOptions options,
        JosePayloadCryptography? cryptography = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _cryptography = cryptography ?? new JosePayloadCryptography();

        ValidateOptions(options);
    }

    /// <summary>
    /// Fetches and validates the signed manifest. The caller should persist the
    /// returned version and pass it as <paramref name="highestAcceptedVersion"/>
    /// on later calls when durable rollback detection is required.
    /// </summary>
    public async Task<EnvelopeKeyManifest> FetchAsync(
        long? highestAcceptedVersion = null,
        CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, _options.ManifestUri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(ManifestMediaType));

        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();
        ValidateFinalUri(response.RequestMessage?.RequestUri);

        if (!string.Equals(response.Content.Headers.ContentType?.MediaType, ManifestMediaType, StringComparison.OrdinalIgnoreCase))
        {
            throw new EnvelopeProtocolException("The key manifest response has an unsupported content type.");
        }

        if (response.Content.Headers.ContentLength is > MaximumManifestBytes)
        {
            throw new EnvelopeProtocolException("The key manifest response exceeds the configured size limit.");
        }

        var body = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
        if (body.Length == 0 || body.Any(value => value > 0x7f))
        {
            throw new EnvelopeProtocolException("The key manifest response is not a compact ASCII JWS.");
        }

        var compactJws = Encoding.ASCII.GetString(body);
        using var rootKey = EnvelopeJwkKeyConverter.ImportPublicEcdsa(
            _options.TrustedRootPublicJwk,
            _options.TrustedRootKeyId);

        var payload = _cryptography.VerifyCompactJws(
            compactJws,
            rootKey,
            _options.TrustedRootKeyId,
            ManifestJwsType);

        EnvelopeKeyManifest manifest;
        try
        {
            manifest = EnvelopeProtocolJson.Deserialize<EnvelopeKeyManifest>(payload);
        }
        catch (JsonException exception)
        {
            throw new EnvelopeProtocolException("The signed key manifest payload is malformed.", exception);
        }

        EnvelopeKeyManifestValidator.Validate(
            manifest,
            _options.ExpectedIssuer,
            _options.ExpectedAudience,
            TimeProvider.System.GetUtcNow(),
            _options.MaximumFreshness,
            _options.ClockSkew,
            highestAcceptedVersion);

        return manifest;
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[8192];

        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (output.Length + read > MaximumManifestBytes)
            {
                throw new EnvelopeProtocolException("The key manifest response exceeds the configured size limit.");
            }

            output.Write(buffer, 0, read);
        }

        return output.ToArray();
    }

    private void ValidateFinalUri(Uri? finalUri)
    {
        if (finalUri is null ||
            !IsPermittedScheme(finalUri) ||
            !SameOrigin(_options.ManifestUri, finalUri))
        {
            throw new EnvelopeProtocolException("The key manifest request changed to an untrusted origin.");
        }
    }

    private static void ValidateOptions(EnvelopeKeyManifestClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options.ManifestUri);

        if (!IsPermittedScheme(options.ManifestUri))
        {
            throw new ArgumentException("The manifest URI must use HTTPS. HTTP is allowed only for loopback development.", nameof(options));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(options.ExpectedIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ExpectedAudience);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.TrustedRootKeyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.TrustedRootPublicJwk);

        if (options.MaximumFreshness <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Maximum manifest freshness must be positive.");
        }

        if (options.ClockSkew < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Clock skew cannot be negative.");
        }
    }

    private static bool IsPermittedScheme(Uri uri) =>
        uri.IsAbsoluteUri &&
        (uri.Scheme == Uri.UriSchemeHttps ||
         (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback));

    private static bool SameOrigin(Uri expected, Uri actual) =>
        string.Equals(expected.Scheme, actual.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(expected.Host, actual.Host, StringComparison.OrdinalIgnoreCase) &&
        expected.Port == actual.Port;
}
