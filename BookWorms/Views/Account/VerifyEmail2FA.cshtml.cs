using System.ComponentModel.DataAnnotations;

public class VerifyEmail2FAModel
{
    [Required(ErrorMessage = "Email code is required.")]
    public string Code { get; set; }

    public string UserId { get; set; }
}
