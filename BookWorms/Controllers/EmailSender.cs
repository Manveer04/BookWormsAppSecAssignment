using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using IEmailSender = Microsoft.AspNetCore.Identity.UI.Services.IEmailSender;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;

public class EmailSender : IEmailSender
{
    private readonly IConfiguration _configuration;

    public EmailSender(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        var smtpSettings = _configuration.GetSection("Smtp");

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress("BookWorms", smtpSettings["From"]));
        message.To.Add(new MailboxAddress(email, email));
        message.Subject = subject;

        var bodyBuilder = new BodyBuilder { HtmlBody = htmlMessage };
        message.Body = bodyBuilder.ToMessageBody();

        using (var client = new SmtpClient())
        {
            try
            {
                if (int.Parse(smtpSettings["Port"]) == 465)
                {
                    // ✅ Correct way to use SSL with Port 465
                    await client.ConnectAsync(smtpSettings["Host"], 465, SecureSocketOptions.SslOnConnect);
                }
                else if (int.Parse(smtpSettings["Port"]) == 587)
                {
                    // ✅ Correct way to use STARTTLS with Port 587
                    await client.ConnectAsync(smtpSettings["Host"], 587, SecureSocketOptions.StartTls);
                }

                await client.AuthenticateAsync(smtpSettings["Username"], smtpSettings["Password"]);
                await client.SendAsync(message);
                await client.DisconnectAsync(true);

                Console.WriteLine($"✅ Email sent successfully to {email}");
            }
            catch (SmtpCommandException ex)
            {
                Console.WriteLine($"❌ SMTP Command Error: {ex.Message}");
                throw;
            }
            catch (SmtpProtocolException ex)
            {
                Console.WriteLine($"❌ SMTP Protocol Error: {ex.Message}");
                throw;
            }
        }
    }
}
