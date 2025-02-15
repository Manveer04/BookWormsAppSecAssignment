using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;

public class ApplicationUser : IdentityUser
{
    private readonly byte[] EncryptionKey;

    public ApplicationUser()
    {
        // Load Encryption Key from appsettings.json
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json")
            .Build();

        string keyString = configuration["EncryptionSettings:Key"];
        if (string.IsNullOrEmpty(keyString))
        {
            throw new Exception("Encryption key is missing. Ensure it is set in appsettings.json.");
        }

        try
        {
            EncryptionKey = Convert.FromBase64String(keyString); // ✅ Correctly decodes Base64 key
            if (EncryptionKey.Length != 32)
            {
                throw new Exception("Invalid AES key length. It must be 32 bytes (256 bits).");
            }
        }
        catch (FormatException)
        {
            throw new Exception("Encryption key in appsettings.json is not a valid Base64 string.");
        }
    }

    private string _firstName;
    private string _lastName;
    private string _creditCardNo;
    private string _billingAddress;
    private string _shippingAddress;
    private string _email;
    private string _mobileNo;
    private string _photoPath;
    public List<PasswordHistory> PasswordHistories { get; set; } = new List<PasswordHistory>();
    public DateTime PasswordLastChanged { get; set; }
    //public bool Is2FAEnabled { get; set; }
    public string TwoFactorType { get; set; } = "None"; // "GoogleAuthenticator" or "Email"

    public string FirstName
    {
        get => _firstName;  // No encryption needed for First Name
        set => _firstName = value;
    }


    public string LastName
    {
        get => _lastName;  // No encryption needed for Last Name
        set => _lastName = value;
    }

    public string CreditCardNo
    {
        get => string.IsNullOrEmpty(_creditCardNo) ? _creditCardNo : DecryptData(_creditCardNo);
        set => _creditCardNo = string.IsNullOrEmpty(value) ? value : EncryptData(value);
    }

    public string BillingAddress
    {
        get => string.IsNullOrEmpty(_billingAddress) ? _billingAddress : DecryptData(_billingAddress);
        set => _billingAddress = string.IsNullOrEmpty(value) ? value : EncryptData(value);
    }

    public string ShippingAddress
    {
        get => string.IsNullOrEmpty(_shippingAddress) ? _shippingAddress : DecryptData(_shippingAddress);
        set => _shippingAddress = string.IsNullOrEmpty(value) ? value : EncryptData(value);
    }

    public override string Email
    {
        get => _email;  // No encryption needed for file paths
        set => _email = value;
    }

    public string MobileNo
    {
        get => string.IsNullOrEmpty(_mobileNo) ? _mobileNo : DecryptData(_mobileNo);
        set => _mobileNo = string.IsNullOrEmpty(value) ? value : EncryptData(value);
    }

    public string PhotoPath
    {
        get => _photoPath;  // No encryption needed for file paths
        set => _photoPath = value;
    }

    public class PasswordHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string PasswordHash { get; set; }
        public DateTime CreatedAt { get; set; }
    }


    private string EncryptData(string data)
    {
        if (string.IsNullOrEmpty(data)) return data;

        using (Aes aes = Aes.Create())
        {
            aes.Key = EncryptionKey;
            aes.IV = new byte[16];

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(data);
                byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                string base64Encrypted = Convert.ToBase64String(encryptedBytes);
                return base64Encrypted;
            }
        }
    }


    private string DecryptData(string encryptedData)
    {
        if (string.IsNullOrEmpty(encryptedData)) return encryptedData;

        try
        {
            byte[] encryptedBytes = Convert.FromBase64String(encryptedData); // ✅ Ensure input is Base64
            using (Aes aes = Aes.Create())
            {
                aes.Key = EncryptionKey;
                aes.IV = new byte[16];
                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
        catch (FormatException ex)
        {
            throw new Exception($"Decryption error: The provided data is not a valid Base64 string. Data: {encryptedData}", ex);
        }
    }

}
