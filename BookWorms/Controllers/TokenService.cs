using System;
using System.Security.Cryptography;

namespace BookWorms.Services
{
    public class TokenService
    {
        public string GenerateSecureToken(int length)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var tokenData = new byte[length];
                rng.GetBytes(tokenData);
                return Convert.ToBase64String(tokenData);
            }
        }
    }
}
