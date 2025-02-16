using System.ComponentModel.DataAnnotations;

namespace BookWorms.Models
{
    public class ConfirmEnableEmail2FAViewModel
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Token { get; set; }

        [Required(ErrorMessage = "Please enter the 2FA code sent to your email.")]
        [Display(Name = "2FA Code")]
        public string Code { get; set; }
    }
}
