using Twilio;
using Twilio.Rest.Verify.V2.Service;
using Microsoft.Extensions.Configuration;

public class TwilioService
{
    private readonly string _accountSid;
    private readonly string _authToken;
    private readonly string _serviceSid;

    public TwilioService(IConfiguration configuration)
    {
        _accountSid = configuration["Twilio:AccountSid"];
        _authToken = configuration["Twilio:AuthToken"];
        _serviceSid = configuration["Twilio:ServiceSid"];
        TwilioClient.Init(_accountSid, _authToken);
    }

    public async Task SendVerificationAsync(string phoneNumber)
    {
        var verification = await VerificationResource.CreateAsync(
            to: phoneNumber,
            channel: "sms",
            pathServiceSid: _serviceSid
        );
    }

    public async Task<bool> CheckVerificationAsync(string phoneNumber, string code)
    {
        var verificationCheck = await VerificationCheckResource.CreateAsync(
            to: phoneNumber,
            code: code,
            pathServiceSid: _serviceSid
        );

        return verificationCheck.Status == "approved";
    }
}
