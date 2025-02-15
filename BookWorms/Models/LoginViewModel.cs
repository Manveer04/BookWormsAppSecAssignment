using System.ComponentModel.DataAnnotations;

public class LoginViewModel
{
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    public bool RememberMe { get; set; }

    public bool IsLockedOut { get; set; }
    public string LockoutMessage { get; set; } = string.Empty;

    [Required(ErrorMessage = "reCAPTCHA validation is required.")]
    public string gRecaptchaResponse { get; set; }
}
