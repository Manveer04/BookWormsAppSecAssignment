namespace BookWorms.Services
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity.UI.Services;

    public class AccountService
    {
        private readonly TokenService _tokenService;
        private readonly IEmailSender _emailSender;
        private readonly TwilioService _twilioService;

        public AccountService(TokenService tokenService, IEmailSender emailSender, TwilioService twilioService)
        {
            _tokenService = tokenService;
            _emailSender = emailSender;
            _twilioService = twilioService;
        }

        public async Task SendPasswordResetSmsAsync(string phoneNumber)
        {
            await _twilioService.SendVerificationAsync(phoneNumber);
        }

        public async Task<bool> VerifyPasswordResetSmsAsync(string phoneNumber, string code)
        {
            return await _twilioService.CheckVerificationAsync(phoneNumber, code);
        }

        public async Task SendPasswordResetEmailAsync(string email)
        {
            var token = _tokenService.GenerateSecureToken(32);

            var callbackUrl = $"https://localhost:7263/Account/ResetPassword?token={token}&email={email}";

            await _emailSender.SendEmailAsync(email, "Reset Password",
                $"Please reset your password by <a href='{callbackUrl}'>clicking here</a>.");
        }
    }
}
