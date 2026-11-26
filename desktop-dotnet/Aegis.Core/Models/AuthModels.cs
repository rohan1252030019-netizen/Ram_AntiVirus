using System.Text.Json.Serialization;
using Aegis.Core.Enums;

namespace Aegis.Core.Models;

public record UserDto(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("role")] UserRole Role,
    [property: JsonPropertyName("client_id")] string? ClientId = null,
    [property: JsonPropertyName("is_active")] bool IsActive = true
);

public record UserLoginRequest(
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("password")] string Password
);

public record UserLoginResponse(
    [property: JsonPropertyName("token")] string Token,
    [property: JsonPropertyName("user")] UserDto User
);

public record ClientLoginRequest(
    [property: JsonPropertyName("api_key")] string ApiKey
);

public record ClientLoginResponse(
    [property: JsonPropertyName("token")] string Token,
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("client_name")] string ClientName
);
