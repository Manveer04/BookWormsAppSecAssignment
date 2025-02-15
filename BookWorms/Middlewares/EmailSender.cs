namespace BookWorms.Middlewares
{
    using Microsoft.AspNetCore.Identity.UI.Services;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.Logging;
    using System;
    using System.Net;
    using System.Net.Mail;
    using System.Threading.Tasks;

    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(IConfiguration configuration, ILogger<EmailSender> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var smtpSettings = _configuration.GetSection("Smtp");
            var host = smtpSettings["Host"];
            var port = smtpSettings["Port"];
            var username = smtpSettings["Username"];
            var password = smtpSettings["Password"];
            var enableSsl = smtpSettings["EnableSsl"];
            var from = smtpSettings["From"];

            if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(port) || string.IsNullOrEmpty(username) ||
                string.IsNullOrEmpty(password) || string.IsNullOrEmpty(enableSsl) || string.IsNullOrEmpty(from))
            {
                _logger.LogError("SMTP settings are not configured properly.");
                throw new InvalidOperationException("SMTP settings are not configured properly.");
            }

            try
            {
                _logger.LogInformation("Sending email to {Email}", email);

                var smtpClient = new SmtpClient(host)
                {
                    Port = int.Parse(port),
                    Credentials = new NetworkCredential(username, password),
                    EnableSsl = bool.Parse(enableSsl)
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(from),
                    Subject = subject,
                    Body = htmlMessage,
                    IsBodyHtml = true,
                };
                mailMessage.To.Add(email);

                await smtpClient.SendMailAsync(mailMessage);

                _logger.LogInformation("Email sent to {Email} successfully", email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending email to {Email}", email);
                throw;
            }
        }
    }
}
