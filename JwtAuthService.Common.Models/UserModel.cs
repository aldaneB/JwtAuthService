namespace JwtAuthService.Common.Models;

public class UserModel
{
    public string Username { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string EmailAddress { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
}

