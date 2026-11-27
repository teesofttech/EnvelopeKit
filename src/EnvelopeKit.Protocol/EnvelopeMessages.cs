using System.Text.Json;
using System.Text.Json.Serialization;

namespace EnvelopeKit.Protocol;

/// <summary>
/// Provisional request wire envelope. Field names and version are not yet a stable protocol.
/// </summary>
public sealed record EnvelopeRequestMessage
{
    public const int DraftVersion = 1;

    [JsonPropertyName("version")]
    public int Version { get; init; } = DraftVersion;

    [JsonPropertyName("requestId")]
    public required string RequestId { get; init; }

    [JsonPropertyName("issuedAt")]
    public long IssuedAt { get; init; }

    [JsonPropertyName("expiresAt")]
    public long ExpiresAt { get; init; }

    [JsonPropertyName("method")]
    public required string Method { get; init; }

    [JsonPropertyName("target")]
    public required string Target { get; init; }

    [JsonPropertyName("responsePublicKey")]
    public required JsonElement ResponsePublicKey { get; init; }

    [JsonPropertyName("body")]
    public required JsonElement Body { get; init; }
}

/// <summary>
/// Provisional signed response payload. Field names and version are not yet a stable protocol.
/// </summary>
public sealed record EnvelopeResponseMessage
{
    public const int DraftVersion = 1;

    [JsonPropertyName("version")]
    public int Version { get; init; } = DraftVersion;

    [JsonPropertyName("requestId")]
    public required string RequestId { get; init; }

    [JsonPropertyName("status")]
    public int Status { get; init; }

    [JsonPropertyName("contentType")]
    public required string ContentType { get; init; }

    [JsonPropertyName("body")]
    public required JsonElement Body { get; init; }
}

/// <summary>
/// JSON settings used by the provisional protocol records.
/// Unknown fields are rejected so a caller cannot silently accept an unrecognised
/// message shape as if it were the current draft.
/// </summary>
public static class EnvelopeProtocolJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 32,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static byte[] Serialize<T>(T message) =>
        JsonSerializer.SerializeToUtf8Bytes(message, Options);

    public static T Deserialize<T>(ReadOnlySpan<byte> utf8Json) =>
        JsonSerializer.Deserialize<T>(utf8Json, Options)
        ?? throw new JsonException("The protocol message was empty.");
}
