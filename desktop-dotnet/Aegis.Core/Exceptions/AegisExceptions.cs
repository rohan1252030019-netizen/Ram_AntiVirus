namespace Aegis.Core.Exceptions;

public class AegisApiException : Exception
{
    public int? StatusCode { get; }
    public AegisApiException(string message, int? statusCode = null, Exception? inner = null)
        : base(message, inner)
    {
        StatusCode = statusCode;
    }
}

public class AegisUnauthorizedException : AegisApiException
{
    public AegisUnauthorizedException(string message = "Session expired or invalid. Please log in again.")
        : base(message, 401) { }
}

public class AegisForbiddenException : AegisApiException
{
    public AegisForbiddenException(string message = "Access denied: not permitted for your role.")
        : base(message, 403) { }
}

public class AegisNetworkException : AegisApiException
{
    public AegisNetworkException(string message = "Network connection failed. Backend unreachable.", Exception? inner = null)
        : base(message, null, inner) { }
}
