using System.ComponentModel.DataAnnotations;

public class VerifyGoogleAuthenticatorModel
{
    [Required(ErrorMessage = "Authenticator code is required.")]
    public string Code { get; set; }
}
