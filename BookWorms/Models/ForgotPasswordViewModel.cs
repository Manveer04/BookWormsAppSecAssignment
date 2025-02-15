using System.ComponentModel.DataAnnotations;

public class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    public string Email { get; set; }

    //[Required(ErrorMessage = "Mobile Number is required.")]
    //public string MobileNo { get; set; }
    //// Honeypot field
    //public string Honeypot { get; set; }
}
