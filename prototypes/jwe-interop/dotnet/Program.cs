using System.Security.Cryptography;
using System.Text.Json;
using Jose;

const string ApiEncryptionKeyId = "api-enc-1";
const string ApiSigningKeyId = "api-sig-1";
var dataDirectory = Environment.GetEnvironmentVariable("ENVELOPEKIT_SPIKE_DATA")
    ?? throw new InvalidOperationException("ENVELOPEKIT_SPIKE_DATA must point to a temporary directory.");
Directory.CreateDirectory(dataDirectory);

if (args.Length != 1)
{
    throw new ArgumentException("Usage: JweInterop <setup|process-request>");
}

switch (args[0])
{
    case "setup":
        WriteKeyPair("api-encryption", ApiEncryptionKeyId, "enc");
        WriteKeyPair("api-signing", ApiSigningKeyId, "sig");
        Console.WriteLine("Generated temporary P-256 API encryption and signing keys.");
        break;
    case "process-request":
        ProcessRequest();
        break;
    default:
        throw new ArgumentException($"Unknown command: {args[0]}");
}

void ProcessRequest()
{
    var requestJwe = File.ReadAllText(Path.Combine(dataDirectory, "request.jwe"));
    var apiEncryptionPrivateKey = Jwk.FromJson(File.ReadAllText(Path.Combine(dataDirectory, "api-encryption.private.jwk.json")));
    var plaintext = JWT.Decode(requestJwe, apiEncryptionPrivateKey, JweAlgorithm.ECDH_ES, JweEncryption.A256GCM);

    using var requestDocument = JsonDocument.Parse(plaintext);
    var requestRoot = requestDocument.RootElement;
    var requestId = requestRoot.GetProperty("requestId").GetString()
        ?? throw new InvalidOperationException("Missing requestId.");
    var clientPublicKeyJson = requestRoot.GetProperty("responsePublicKey").GetRawText();
    var clientPublicKey = Jwk.FromJson(clientPublicKeyJson);
    var echoedBody = requestRoot.GetProperty("body");
    var response = JsonSerializer.Serialize(new
    {
        version = 1,
        requestId,
        status = 200,
        body = new
        {
            accepted = true,
            echoed = echoedBody
        }
    });

    var apiSigningPrivateKey = Jwk.FromJson(File.ReadAllText(Path.Combine(dataDirectory, "api-signing.private.jwk.json")));
    var signedResponse = JWT.Encode(
        response,
        apiSigningPrivateKey,
        JwsAlgorithm.ES256,
        extraHeaders: new Dictionary<string, object> { ["kid"] = ApiSigningKeyId });

    var encryptedResponse = JWT.Encode(
        signedResponse,
        clientPublicKey,
        JweAlgorithm.ECDH_ES,
        JweEncryption.A256GCM,
        extraHeaders: new Dictionary<string, object> { ["kid"] = "client-response-1" });

    File.WriteAllText(Path.Combine(dataDirectory, "response.jwe"), encryptedResponse);
    Console.WriteLine(".NET decrypted the browser request, signed the response, and encrypted it to the browser key.");
}

void WriteKeyPair(string name, string keyId, string use)
{
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var privateParameters = key.ExportParameters(includePrivateParameters: true);
    var publicParameters = key.ExportParameters(includePrivateParameters: false);
    var privateJwk = new Dictionary<string, object?>
    {
        ["kty"] = "EC",
        ["crv"] = "P-256",
        ["x"] = Base64Url(publicParameters.Q.X!),
        ["y"] = Base64Url(publicParameters.Q.Y!),
        ["d"] = Base64Url(privateParameters.D!),
        ["kid"] = keyId,
        ["use"] = use
    };
    var publicJwk = new Dictionary<string, object?>
    {
        ["kty"] = "EC",
        ["crv"] = "P-256",
        ["x"] = Base64Url(publicParameters.Q.X!),
        ["y"] = Base64Url(publicParameters.Q.Y!),
        ["kid"] = keyId,
        ["use"] = use
    };
    File.WriteAllText(Path.Combine(dataDirectory, $"{name}.private.jwk.json"), JsonSerializer.Serialize(privateJwk));
    File.WriteAllText(Path.Combine(dataDirectory, $"{name}.public.jwk.json"), JsonSerializer.Serialize(publicJwk));
}

static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
