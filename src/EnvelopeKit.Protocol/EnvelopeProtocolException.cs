namespace EnvelopeKit.Protocol;

/// <summary>Raised when an EnvelopeKit protocol message fails structural validation.</summary>
public sealed class EnvelopeProtocolException : Exception
{
    public EnvelopeProtocolException(string message)
        : base(message)
    {
    }

    public EnvelopeProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
