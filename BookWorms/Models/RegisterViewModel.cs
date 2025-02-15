using System.ComponentModel.DataAnnotations;

public class RegisterViewModel
{
    [Required(ErrorMessage = "First name is required.")]
    [MinLength(2, ErrorMessage = "First name must be at least 2 characters long.")]
    public string FirstName { get; set; }

    [Required(ErrorMessage = "Last name is required.")]
    [MinLength(2, ErrorMessage = "Last name must be at least 2 characters long.")]
    public string LastName { get; set; }

    [Required(ErrorMessage = "Credit card number is required.")]
    [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit card number must be 16 digits long.")]
    public string CreditCardNo { get; set; }

    [Required(ErrorMessage = "Mobile number is required.")]
    [RegularExpression(@"^\d{10}$", ErrorMessage = "Mobile number must be 10 digits long.")]
    public string MobileNo { get; set; }

    [Required(ErrorMessage = "Billing address is required.")]
    public string BillingAddress { get; set; }

    [Required(ErrorMessage = "Shipping address is required.")]
    public string ShippingAddress { get; set; }

    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters long.")]
    public string Password { get; set; }

    [Required(ErrorMessage = "Confirm password is required.")]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "Passwords do not match.")]
    public string ConfirmPassword { get; set; }

    [Required(ErrorMessage = "Profile photo is required.")]
    [DataType(DataType.Upload)]
    [AllowedExtensions(new string[] { ".jpg" })]
    public IFormFile Photo { get; set; }

    [Required(ErrorMessage = "reCAPTCHA validation is required.")]
    public string gRecaptchaResponse { get; set; }
}
