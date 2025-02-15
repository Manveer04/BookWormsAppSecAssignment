using System.ComponentModel.DataAnnotations;

public class EnableEmail2FAModel
{
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    public string Email { get; set; }
}
