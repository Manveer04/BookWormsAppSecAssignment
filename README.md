# BookWorms Online - Secure Bookstore Application

## 📖 Overview

BookWorms Online is a comprehensive ASP.NET Core web application developed as part of an Application Security assignment. This secure bookstore service implements robust security features including membership registration, data encryption, session management, two-factor authentication, and comprehensive input validation.

## 🏗️ Architecture

- **Framework**: ASP.NET Core 8.0
- **Database**: SQL Server LocalDB
- **Authentication**: ASP.NET Core Identity
- **ORM**: Entity Framework Core
- **Logging**: Serilog
- **Frontend**: Razor Pages with Bootstrap

## 🚀 Features Implemented

### 1. Registration Form 

The membership registration form includes all required fields:
- ✅ First Name
- ✅ Last Name  
- ✅ Credit Card Number (Encrypted in database)
- ✅ Mobile Number
- ✅ Billing Address
- ✅ Shipping Address (Allows special characters)
- ✅ Email Address (Unique validation implemented)
- ✅ Password
- ✅ Confirm Password
- ✅ Photo Upload (.JPG only)

**Key Implementation Details:**
- Duplicate email detection and prevention
- Server-side validation for all fields
- Automatic data sanitization using `HtmlSanitizer`

### 2. Password Security

**Strong Password Requirements:**
- ✅ Minimum 12 characters
- ✅ Combination of lowercase, uppercase, numbers, and special characters
- ✅ Real-time password strength feedback
- ✅ Both client-side and server-side validation

**Implementation:**
```csharp
// Password policy configuration in Program.cs
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
});
```

### 3. Data Encryption & Security

**Features:**
- ✅ Password hashing using ASP.NET Identity
- ✅ AES-256 encryption for sensitive customer data (Credit Card, Personal Info)
- ✅ Data decryption for display on homepage
- ✅ Secure key management via configuration

**Encryption Implementation:**
- Credit card numbers encrypted before database storage
- Personal information encrypted using AES-256
- Encryption keys stored securely in `appsettings.json`

### 4. Session Management

**Features:**
- ✅ Secure session creation upon login
- ✅ Session timeout (configurable - currently 30 minutes)
- ✅ Automatic redirect on session expiry
- ✅ Multiple login detection from different devices
- ✅ Custom session middleware implementation

**Session Configuration:**
```csharp
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
```

### 5. Login/Logout & Audit Logging

**Features:**
- ✅ Secure credential verification
- ✅ Rate limiting (Account lockout after 5 failed attempts)
- ✅ Comprehensive audit logging
- ✅ Safe logout with session cleanup
- ✅ Homepage displays user info including decrypted data
- ✅ User activity tracking in database

**Rate Limiting Configuration:**
```csharp
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
});
```

### 6. Anti-Bot Protection

**Implementation:**
- ✅ Google reCAPTCHA v3 integration
- ✅ Server-side reCAPTCHA validation
- ✅ Seamless user experience

### 7. Input Validation & Security

**Security Measures:**
- ✅ SQL Injection prevention using Entity Framework
- ✅ XSS protection using `HtmlSanitizer`
- ✅ CSRF protection with anti-forgery tokens
- ✅ Client and server-side validation
- ✅ Proper input sanitization and encoding
- ✅ Custom validation attributes

**Validation Features:**
- Email format validation
- Phone number format validation
- File upload restrictions (.JPG only)
- SQL injection prevention through parameterized queries

### 8. Error Handling

**Features:**
- ✅ Custom error pages (404, 403, 500)
- ✅ Graceful error handling across all pages
- ✅ Comprehensive logging with Serilog
- ✅ User-friendly error messages

### 9. Advanced Features

**Account Policies:**
- ✅ Automatic account recovery after lockout period
- ✅ Password history (prevents last 2 passwords)
- ✅ Change password functionality
- ✅ Reset password via email/SMS
- ✅ Password age policies (minimum/maximum)

**Implementation:**
- Password history tracking in database
- Automatic unlocking after specified time
- Email and SMS-based password recovery

### 10. Two-Factor Authentication

**Features:**
- ✅ Email-based 2FA
- ✅ SMS-based 2FA (Twilio integration)
- ✅ QR code generation for authenticator apps
- ✅ Backup codes for account recovery

## 🛠️ Installation & Setup

### Prerequisites
- .NET 8.0 SDK
- SQL Server LocalDB
- Visual Studio 2022 or VS Code

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone [repository-url]
   cd BookWormsAppSecAssignment-main/BookWorms
   ```

2. **Configure database:**
   ```bash
   dotnet ef database update
   ```

3. **Configure settings:**
   Update `appsettings.json` with your configuration:
   ```json
   {
     "Recaptcha": {
       "SiteKey": "your-site-key",
       "SecretKey": "your-secret-key"
     },
     "Twilio": {
       "AccountSid": "your-account-sid",
       "AuthToken": "your-auth-token",
       "ServiceSid": "your-service-sid"
     },
     "Smtp": {
       "Host": "smtp.gmail.com",
       "Username": "your-email@gmail.com",
       "Password": "your-app-password"
     }
   }
   ```

4. **Run the application:**
   ```bash
   dotnet run
   ```

5. **Access the application:**
   Navigate to `https://localhost:7263`

## 🔧 Configuration

### Database Configuration
The application uses SQL Server LocalDB by default. Connection string in `appsettings.json`:
```json
"ConnectionStrings": {
  "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=aspnet-BookWorms;Trusted_Connection=True;MultipleActiveResultSets=true"
}
```

### Security Configuration
- **Encryption Key**: Stored in `appsettings.json` (Base64 encoded)
- **Session Timeout**: Configurable in `appsettings.json`
- **Rate Limiting**: IP-based rate limiting configured
- **Password Policies**: Enforced through ASP.NET Identity

## 📊 Security Testing

### Static Code Analysis

The application has been tested using:
- **GitHub CodeQL Analysis**
- **Manual security review**

### Security Vulnerabilities Addressed
1. ✅ SQL Injection Prevention
2. ✅ XSS Attack Mitigation
3. ✅ CSRF Protection
4. ✅ Session Fixation Prevention
5. ✅ Sensitive Data Encryption
6. ✅ Secure Password Storage
7. ✅ Rate Limiting Implementation

## 📁 Project Structure

```
BookWorms/
├── Controllers/           # MVC Controllers
│   ├── AccountController.cs
│   ├── HomeController.cs
│   └── TwoFactorController.cs
├── Models/               # Data Models & ViewModels
│   ├── ApplicationUser.cs
│   ├── RegisterViewModel.cs
│   └── LoginViewModel.cs
├── Views/                # Razor Views
├── Middlewares/          # Custom Middleware
│   ├── SessionMiddleware.cs
│   └── AuditLogService.cs
├── Data/                 # Database Context
├── Migrations/           # EF Migrations
└── wwwroot/             # Static Files
```

## 🚦 Testing

### Unit Tests
- Model validation tests
- Controller action tests
- Security feature tests

### Integration Tests
- End-to-end registration flow
- Authentication and authorization
- Session management tests

### Security Tests
- Input validation testing
- Authentication bypass attempts
- Session security validation

## 📈 Performance & Monitoring

### Logging
- **Serilog** implementation for comprehensive logging
- File-based logging with daily rotation
- Console logging for development
- Audit trail for security events

### Monitoring Features
- Failed login attempt tracking
- Session activity monitoring
- User behavior analytics
- Security event alerting

## 🛡️ Security Features Summary

| Feature | Implementation | Status |
|---------|---------------|---------|
| Password Complexity | 12+ chars, mixed case, numbers, symbols | ✅ |
| Data Encryption | AES-256 for sensitive data | ✅ |
| Session Security | Timeout, multi-device detection | ✅ |
| Rate Limiting | 5 failed attempts = lockout | ✅ |
| 2FA | Email, SMS, Authenticator app | ✅ |
| Input Validation | Client & server-side | ✅ |
| XSS Protection | HtmlSanitizer implementation | ✅ |
| SQL Injection | Entity Framework protection | ✅ |
| CSRF Protection | Anti-forgery tokens | ✅ |
| Error Handling | Custom pages, logging | ✅ |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement security best practices
4. Add comprehensive tests
5. Submit a pull request

## 📄 License

This project is developed for educational purposes as part of an Application Security assignment.

## 👥 Team

**Developer**: Manveer Singh Daljit Singh
**Course**: Application Security  
**Institution**: Nanyang Polytechnic

## 📞 Support

For any security concerns or issues, please contact the development team immediately.

---

**Note**: This application implements enterprise-level security features and follows OWASP security guidelines. All sensitive data is encrypted, and comprehensive audit logging is maintained for security compliance.
