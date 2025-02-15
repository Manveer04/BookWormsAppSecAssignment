public class Manage2FAModel
{
    public bool TwoFactorEnable { get; set; }
    public string TwoFactorType { get; set; } // "GoogleAuthenticator" or "Email"
}

