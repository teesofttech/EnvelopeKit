using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EnvelopeKit.Cryptography;
using EnvelopeKit.Protocol;

namespace EnvelopeKit.Http;

/// <summary>
/// Sends a JSON HTTP request as an encrypted EnvelopeKit message, then verifies
/// and decrypts the signed and encrypted JSON response.
/// </summary>
/// <remarks>
/// This API uses the provisional v1 message records. Configure the supplied
/// <see cref="HttpClient"/> transport not to follow redirects, so credentials
/// and protected requests are never forwarded to a different origin.
/// </remarks>
public sealed class EnvelopeHttpClient
{
    private const string JoseMediaType = "application/jose";
    private const string ResponseJwsType = "application/envelopekit-response+jws";
    private const int MaximumPayloadBytes = 4 * 1024 * 1024;

    private readonly HttpClient _httpClient;
    private readonly EnvelopeKeyManifestClient _manifestClient;
    private readonly JosePayloadCryptography _cryptography;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _requestLifetime;

    public EnvelopeHttpClient(
        HttpClient httpClient,
        EnvelopeKeyManifestClient manifestClient,
        TimeSpan? requestLifetime = null,
        JosePayloadCryptography? cryptography = null,
        TimeProvider? timeProvider = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _manifestClient = manifestClient ?? throw new ArgumentNullException(nameof(manifestClient));
        _cryptography = cryptography ?? new JosePayloadCryptography();
        _timeProvider = timeProvider ?? TimeProvider.System;
        _requestLifetime = requestLifetime ?? TimeSpan.FromSeconds(60);

        if (_requestLifetime <= TimeSpan.Zero || _requestLifetime > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(requestLifetime), "Request lifetime must be greater than zero and no longer than five minutes.");
        }
    }

    /// <summary>
    /// Sends a JSON request to the same API origin and returns the verified
    /// application response as ordinary JSON content.
    /// </summary>
    public async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        long? highestAcceptedManifestVersion = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var uri = request.RequestUri ?? throw new ArgumentException("The request must have a URI.", nameof(request));

        if (!uri.IsAbsoluteUri || !IsPermittedScheme(uri))
        {
            throw new ArgumentException("The request URI must be HTTPS. HTTP is allowed only for loopback development.", nameof(request));
        }

        var now = _timeProvider.GetUtcNow();
        var manifest = await _manifestClient.FetchAsync(highestAcceptedManifestVersion, cancellationToken).ConfigureAwait(false);
        var encryptionKey = SelectActiveKey(manifest, "enc", now);

        var bodyBytes = request.Content is null
            ? "{}"u8.ToArray()
            : await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (bodyBytes.Length > MaximumPayloadBytes)
        {
            throw new EnvelopeProtocolException("The request body exceeds the EnvelopeKit client size limit.");
        }

        JsonElement body;
        try
        {
            using var bodyDocument = JsonDocument.Parse(bodyBytes);
            body = bodyDocument.RootElement.Clone();
        }
        catch (JsonException exception)
        {
            throw new EnvelopeProtocolException("EnvelopeKit can protect JSON request bodies only.", exception);
        }

        var requestId = Base64UrlEncode(RandomNumberGenerator.GetBytes(16));
        using var responseKey = EnvelopeP256KeyGenerator.CreateClientResponseDecryptionKey();
        var responseKeyId = $"response-{requestId}";
        var responsePublicJwk = EnvelopeJwkKeyConverter.ExportPublicEcdh(responseKey, responseKeyId);
        using var responsePublicDocument = JsonDocument.Parse(responsePublicJwk);

        var issuedAt = now.ToUnixTimeSeconds();
        var expiresAt = now.Add(_requestLifetime).ToUnixTimeSeconds();
        var envelope = new EnvelopeRequestMessage
        {
            RequestId = requestId,
            IssuedAt = issuedAt,
            ExpiresAt = expiresAt,
            Method = request.Method.Method.ToUpperInvariant(),
            Target = uri.PathAndQuery,
            ResponsePublicKey = responsePublicDocument.RootElement.Clone(),
            Body = body
        };

        using var apiEncryptionKey = EnvelopeJwkKeyConverter.ImportPublicEcdh(
            encryptionKey.JsonWebKey.GetRawText(),
            encryptionKey.KeyId);
        var compactJwe = _cryptography.EncryptCompactJwe(
            EnvelopeProtocolJson.Serialize(envelope),
            apiEncryptionKey,
            encryptionKey.KeyId);

        using var outerRequest = new HttpRequestMessage(request.Method, uri)
        {
            Version = request.Version,
            VersionPolicy = request.VersionPolicy,
            Content = new StringContent(compactJwe, Encoding.ASCII, JoseMediaType)
        };

        foreach (var header in request.Headers)
        {
            if (!string.Equals(header.Key, "Host", StringComparison.OrdinalIgnoreCase))
            {
                outerRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        using var outerResponse = await _httpClient.SendAsync(
            outerRequest,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);

        if (outerResponse.RequestMessage?.RequestUri is not { } finalUri ||
            !SameOrigin(uri, finalUri) ||
            !IsPermittedScheme(finalUri))
        {
            throw new EnvelopeProtocolException("The protected API request changed to an untrusted origin.");
        }

        if (outerResponse.StatusCode != HttpStatusCode.OK ||
            !string.Equals(outerResponse.Content.Headers.ContentType?.MediaType, JoseMediaType, StringComparison.OrdinalIgnoreCase))
        {
            throw new EnvelopeProtocolException("The API did not return an encrypted EnvelopeKit response.");
        }

        var compactJweResponse = await ReadBoundedAsciiAsync(outerResponse.Content, cancellationToken).ConfigureAwait(false);
        var signedResponse = _cryptography.DecryptCompactJwe(compactJweResponse, responseKey, responseKeyId);
        var compactJws = Encoding.ASCII.GetString(signedResponse);
        var signingKeyId = ReadCompactJwsKeyId(compactJws);
        var signingKey = manifest.Keys.SingleOrDefault(key =>
            key.Use == "sig" &&
            string.Equals(key.KeyId, signingKeyId, StringComparison.Ordinal) &&
            key.NotBefore <= now.ToUnixTimeSeconds() &&
            key.ExpiresAt > now.ToUnixTimeSeconds())
            ?? throw new EnvelopeProtocolException("The response uses an unknown or inactive signing key.");
        using var apiSigningKey = EnvelopeJwkKeyConverter.ImportPublicEcdsa(
            signingKey.JsonWebKey.GetRawText(),
            signingKey.KeyId);
        var responsePayload = _cryptography.VerifyCompactJws(
            compactJws,
            apiSigningKey,
            signingKey.KeyId,
            ResponseJwsType);

        EnvelopeResponseMessage verifiedResponse;
        try
        {
            verifiedResponse = EnvelopeProtocolJson.Deserialize<EnvelopeResponseMessage>(responsePayload);
        }
        catch (JsonException exception)
        {
            throw new EnvelopeProtocolException("The signed API response payload is malformed.", exception);
        }

        if (verifiedResponse.Version != EnvelopeResponseMessage.DraftVersion ||
            !string.Equals(verifiedResponse.RequestId, requestId, StringComparison.Ordinal) ||
            verifiedResponse.Status is < 100 or > 599 ||
            !IsJsonMediaType(verifiedResponse.ContentType))
        {
            throw new EnvelopeProtocolException("The signed API response does not match the protected request.");
        }

        var responseJson = JsonSerializer.SerializeToUtf8Bytes(verifiedResponse.Body, EnvelopeProtocolJson.Options);
        if (responseJson.Length > MaximumPayloadBytes)
        {
            throw new EnvelopeProtocolException("The API response exceeds the EnvelopeKit client size limit.");
        }

        var result = new HttpResponseMessage((HttpStatusCode)verifiedResponse.Status)
        {
            RequestMessage = request,
            Content = new ByteArrayContent(responseJson)
        };
        result.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(verifiedResponse.ContentType);
        return result;
    }

    private static EnvelopeManifestKey SelectActiveKey(
        EnvelopeKeyManifest manifest,
        string use,
        DateTimeOffset now)
    {
        var nowUnix = now.ToUnixTimeSeconds();
        return manifest.Keys
                   .Where(key => key.Use == use && key.NotBefore <= nowUnix && key.ExpiresAt > nowUnix)
                   .OrderByDescending(key => key.NotBefore)
                   .ThenBy(key => key.KeyId, StringComparer.Ordinal)
                   .FirstOrDefault()
               ?? throw new EnvelopeProtocolException($"The signed manifest has no currently valid '{use}' key.");
    }

    private static string ReadCompactJwsKeyId(string compactJws)
    {
        var segments = compactJws.Split('.');
        if (segments.Length != 3 || segments[0].Length == 0)
        {
            throw new EnvelopeProtocolException("The encrypted API response does not contain a compact JWS.");
        }

        try
        {
            var encodedHeader = segments[0].Replace('-', '+').Replace('_', '/');
            encodedHeader = encodedHeader.PadRight(encodedHeader.Length + ((4 - encodedHeader.Length % 4) % 4), '=');
            using var document = JsonDocument.Parse(Convert.FromBase64String(encodedHeader));
            var keyIds = document.RootElement.EnumerateObject()
                .Where(property => property.NameEquals("kid"))
                .ToArray();

            if (keyIds.Length != 1 ||
                keyIds[0].Value.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(keyIds[0].Value.GetString()))
            {
                throw new EnvelopeProtocolException("The response signature has no valid key identifier.");
            }

            return keyIds[0].Value.GetString()!;
        }
        catch (FormatException exception)
        {
            throw new EnvelopeProtocolException("The response signature header is malformed.", exception);
        }
        catch (JsonException exception)
        {
            throw new EnvelopeProtocolException("The response signature header is malformed.", exception);
        }
    }

    private static async Task<string> ReadBoundedAsciiAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaximumPayloadBytes)
        {
            throw new EnvelopeProtocolException("The encrypted API response exceeds the EnvelopeKit client size limit.");
        }

        var bytes = await content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (bytes.Length == 0 || bytes.Length > MaximumPayloadBytes || bytes.Any(value => value > 0x7f))
        {
            throw new EnvelopeProtocolException("The encrypted API response is not a permitted compact JWE.");
        }

        return Encoding.ASCII.GetString(bytes);
    }

    private static bool IsJsonMediaType(string contentType) =>
        string.Equals(contentType, "application/json", StringComparison.OrdinalIgnoreCase) ||
        contentType.EndsWith("+json", StringComparison.OrdinalIgnoreCase);

    private static bool IsPermittedScheme(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttps ||
        (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback);

    private static bool SameOrigin(Uri expected, Uri actual) =>
        string.Equals(expected.Scheme, actual.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(expected.Host, actual.Host, StringComparison.OrdinalIgnoreCase) &&
        expected.Port == actual.Port;

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
