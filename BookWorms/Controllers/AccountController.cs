using BookWorms.Controllers;
using BookWorms.Models;
using BookWorms.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;
using Ganss.Xss;
using Microsoft.AspNetCore.Identity.UI.Services;
using reCAPTCHA.AspNetCore;
using Microsoft.Extensions.Configuration;
using System.IO;
using System;
using System.Text;
using OtpNet;
using System.Security.Cryptography;
using BookWorms.Controllers;
using BookWorms.Services;
using System.Threading;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.SignalR;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Authorization;
using static ApplicationUser;
using QRCoder;
using Twilio.Jwt.AccessToken;
using Microsoft.AspNetCore.Authentication;
using BookWorms.Views.Account;

public class AccountController : Controller
{
    ApplicationDbContext _context;
    private readonly IRecaptchaService _recaptchaService;
    private readonly IConfiguration _configuration;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<AccountController> _logger;
    private readonly string _connectionString;
    private readonly HtmlSanitizer _htmlSanitizer;
    private readonly IEmailSender _emailSender;
    private readonly AccountService _accountService;
    private readonly ExponentialBackoffService _exponentialBackoffService;
    private readonly IHubContext<NotificationHub> _hubContext;
    private readonly AuditLogService _auditLogService;

    public AccountController(
        IHubContext<NotificationHub> hubContext,
        ExponentialBackoffService exponentialBackoffService,
        IRecaptchaService recaptchaService,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILogger<AccountController> logger,
        IConfiguration configuration, 
        IEmailSender emailSender,
        AccountService accountService,
        ApplicationDbContext context,
        AuditLogService auditLogService)
    {
        _exponentialBackoffService = exponentialBackoffService;
        _recaptchaService = recaptchaService;
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
        _connectionString = configuration.GetConnectionString("DefaultConnection"); // ✅ Fetch connection string
        _htmlSanitizer = new HtmlSanitizer();
        _emailSender = emailSender;
        _accountService = accountService;
        _context = context;
        _hubContext = hubContext;
        _auditLogService = auditLogService;
        _configuration = configuration;
    }

    [HttpGet]
    public IActionResult Login(string reason = null)
    {
        if (reason == "timeout")
        {
            ViewBag.Message = "You have been logged out due to inactivity. Please sign in again.";
        }
        else if (reason == "multiplelogin")
        {
            ViewBag.Message = "You have been logged out because your account was signed in from another device or tab.";
        }

        return View(new LoginViewModel
        {
            LockoutMessage = string.Empty,
            IsLockedOut = false
        });
    }



    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(string gRecaptchaResponse, LoginViewModel model, string returnUrl = null)
    {
        _logger.LogInformation("Login attempt received for: {Email}", model.Email);

        if (!await IsReCaptchaValid(model.gRecaptchaResponse))
        {
            _logger.LogWarning("reCAPTCHA validation failed for: {Email}", model.Email);
            ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
            return View(model);
        }

        if (ModelState.IsValid)
        {
            model.Email = _htmlSanitizer.Sanitize(model.Email);
            model.Password = _htmlSanitizer.Sanitize(model.Password);
            _logger.LogDebug("Sanitized Email: {Email}", model.Email);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }

            // ✅ Check if 2FA is enabled and determine the 2FA method
            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                _logger.LogInformation("2FA is enabled for user: {Email}. Checking authentication method...", user.Email);

                if (user.TwoFactorType == "GoogleAuthenticator")
                {
                    _logger.LogInformation("🔑 Google Authenticator is enabled for user: {Email}. Redirecting to Google Authenticator verification.", user.Email);
                    HttpContext.Session.SetString("2FAUserId", user.Id);
                    return RedirectToAction("VerifyGoogleAuthenticator", new { returnUrl, userId = user.Id });
                }
                else if (user.TwoFactorType == "Email")
                {
                    _logger.LogInformation("📧 Email 2FA is enabled for user: {Email}. Generating and sending 2FA code.", user.Email);

                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    _logger.LogInformation("✅ 2FA token generated: {Token} for user: {Email}", token, user.Email);

                    await _emailSender.SendEmailAsync(user.Email, "Your 2FA Code", $"Your 2FA code is: {token}");
                    _logger.LogInformation("📨 Email sent to {Email} with 2FA code", user.Email);

                    // ✅ Store user ID in session before redirecting
                    HttpContext.Session.SetString("2FAUserId", user.Id);

                    return RedirectToAction("VerifyEmail2FA", new { userId = user.Id });
                }
                else
                {
                    _logger.LogWarning("⚠️ Unknown TwoFactorType ({Type}) for user: {Email}. Proceeding with normal login.", user.TwoFactorType, user.Email);
                }
            }

            // ✅ Proceed with normal password authentication if 2FA is not enabled
            var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} logged in successfully.", model.Email);

                // ✅ Log and create session
                await _auditLogService.LogAsync(user.Id, "Login", "User logged in successfully.");

                var newSession = new UserSession
                {
                    UserId = user.Id,
                    SessionId = HttpContext.Session.Id,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                _context.UserSessions.Add(newSession);
                await _context.SaveChangesAsync();

                return RedirectToLocal(returnUrl ?? Url.Action("Home", "Home"));
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User {Email} account locked out.", model.Email);
                ModelState.AddModelError(string.Empty, "Your account is locked. Please try again later.");
                return View(new LoginViewModel { IsLockedOut = true });
            }
            else
            {
                _logger.LogWarning("Invalid login attempt for user {Email}.", model.Email);
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(model);
            }
        }

        _logger.LogWarning("ModelState is invalid. Errors: {Errors}", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage));
        return View(model);
    }






    [HttpGet]
    public async Task<IActionResult> Logout(string reason = null)
    {
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out.");
        return RedirectToAction("Login", new { reason });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        var userId = _userManager.GetUserId(User);
        await _signInManager.SignOutAsync();
        await _auditLogService.LogAsync(userId, "Logout", "User logged out.");
        _logger.LogInformation("User logged out.");
        return RedirectToAction("Index", "Home");
    }





    [HttpGet]
    public IActionResult Register()
    {
        var model = new RegisterViewModel();
        return View(model);
    }



    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model, string gRecaptchaResponse)
    {
        try
        {
            if (!await IsReCaptchaValid(model.gRecaptchaResponse))
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
                return View(model);
            }

            if (!ModelState.IsValid)
            {
                foreach (var modelError in ModelState)
                {
                    foreach (var error in modelError.Value.Errors)
                    {
                        _logger.LogError($"Validation Error: {modelError.Key} - {error.ErrorMessage}");
                    }
                }
                return View(model); // ✅ Reload the form with validation errors
            }

            var user = new ApplicationUser
            {
                FirstName = _htmlSanitizer.Sanitize(model.FirstName),
                LastName = _htmlSanitizer.Sanitize(model.LastName),
                CreditCardNo = _htmlSanitizer.Sanitize(model.CreditCardNo),
                MobileNo = _htmlSanitizer.Sanitize(model.MobileNo),
                BillingAddress = _htmlSanitizer.Sanitize(model.BillingAddress),
                ShippingAddress = _htmlSanitizer.Sanitize(model.ShippingAddress),
                Email = _htmlSanitizer.Sanitize(model.Email),
                UserName = _htmlSanitizer.Sanitize(model.Email),
                EmailConfirmed = true,
                TwoFactorType = "None" // Set default value
            };

            if (model.Photo != null)
            {
                var fileName = Path.GetFileName(model.Photo.FileName);
                var filePath = Path.Combine("wwwroot/uploads", fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await model.Photo.CopyToAsync(stream);
                }

                user.PhotoPath = "/uploads/" + fileName;
            }

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("Login");
            }

            foreach (var error in result.Errors)
            {
                _logger.LogError($"Identity Error: {error.Description}");
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while registering the user.");
            return RedirectToAction("Error", "Home");
        }
    }

    [HttpPost]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableGoogleAuthenticator(string code)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login");
        }
        await _userManager.ResetAuthenticatorKeyAsync(user);

        var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, code);
        if (isValid)
        {
            user.TwoFactorEnabled = true;
            await _userManager.UpdateAsync(user);
            TempData["Message"] = "Settings saved successfully.";
            return RedirectToAction("Manage2FA");
        }

        else
        {
            ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
            return View();
        }
    }


    [HttpGet]
    [Authorize]
    public IActionResult ChangePassword()
    {
        return View();
    }

    [HttpGet]
    public IActionResult VerifyGoogleAuthenticator(string returnUrl = null)
    {
        ViewData["Title"] = "Verify Google Authenticator";
        ViewData["ReturnUrl"] = returnUrl;
        return View(new VerifyGoogleAuthenticatorModel());
    }


    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyGoogleAuthenticator(VerifyGoogleAuthenticatorModel model, string returnUrl = null)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var userId = HttpContext.Session.GetString("2FAUserId");
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("❌ No user ID found in session for Google 2FA verification.");
            return RedirectToAction("Login");
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogError("❌ Unable to find user with ID {UserId} for Google 2FA verification.", userId);
            return RedirectToAction("Login");
        }

        if (!await _userManager.GetTwoFactorEnabledAsync(user))
        {
            _logger.LogWarning("⚠️ User {Email} has not enabled Google Authenticator.", user.Email);
            return RedirectToAction("Login");
        }

        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            _logger.LogError("❌ Authenticator key not found for user: {Email}.", user.Email);
            return RedirectToAction("Login");
        }

        _logger.LogInformation("🔍 Retrieved Authenticator Key for {Email}: {Key}", user.Email, key);

        // Validate TOTP
        var totp = new Totp(Base32Encoding.ToBytes(key));
        bool isCodeValid = totp.VerifyTotp(model.Code, out long timeStepMatched, VerificationWindow.RfcSpecifiedNetworkDelay);

        _logger.LogInformation("🔢 User entered Google Authenticator code: {Code}", model.Code);

        if (isCodeValid)
        {
            _logger.LogInformation("✅ Google Authenticator verification successful for user: {Email}", user.Email);

            // Update security stamp after successful verification
            await _userManager.UpdateSecurityStampAsync(user);
            _logger.LogInformation("🔎 Security stamp updated for user after successful 2FA verification.");

                var userSessions = await _context.UserSessions.Where(us => us.UserId == user.Id && us.IsActive).ToListAsync();
                if (userSessions.Any())
                {
                    foreach (var session in userSessions)
                    {
                        session.IsActive = false;
                    }
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("✅ Deactivated previous user sessions for user: {Email}", user.Email);
                }
                else
                {
                    _logger.LogInformation("ℹ️ No active sessions found for user: {Email}", user.Email);
                }
                await _context.SaveChangesAsync();

                await _hubContext.Clients.User(user.Id).SendAsync("Logout");
                await _signInManager.SignInAsync(user, isPersistent: true);
                _logger.LogInformation("🔑 User {Email} successfully signed in after 2FA.", user.Email);

                var newSession = new UserSession
                {
                    UserId = user.Id,
                    SessionId = HttpContext.Session.Id,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };
                _context.UserSessions.Add(newSession);
                await _context.SaveChangesAsync();

                return RedirectToLocal(returnUrl);
            //}
            //else
            //{
            //    _logger.LogWarning("❌ Sign-in failed after 2FA for user: {Email}", user.Email);
            //    TempData["ErrorMessage"] = "2FA verification failed.";
            //    return RedirectToAction("VerifyGoogleAuthenticator", new { returnUrl });
            //}
        }
        else
        {
            _logger.LogWarning("❌ Invalid Google Authenticator code entered for user: {Email}", user.Email);
            ModelState.AddModelError(string.Empty, "Invalid authenticator code. Please check your time settings or try again.");
            return View(model);
        }
    }





    //[HttpGet]
    //[Authorize]
    //public async Task<IActionResult> EnableEmail2FA()
    //{
    //    var user = await _userManager.GetUserAsync(User);
    //    if (user == null)
    //    {
    //        return NotFound("User not found.");
    //    }

    //    var model = new EnableEmail2FAModel
    //    {
    //        UserId = user.Id
    //    };

    //    return View(model);
    //}


    //[HttpPost]
    //[Authorize]
    //[ValidateAntiForgeryToken]
    //public async Task<IActionResult> EnableEmail2FA(EnableEmail2FAModel model)
    //{
    //    if (!ModelState.IsValid)
    //    {
    //        return View(model);
    //    }

    //    var user = await _userManager.GetUserAsync(User);
    //    if (user == null)
    //    {
    //        return NotFound("User not found.");
    //    }

    //    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

    //    await _emailSender.SendEmailAsync(user.Email, "Enable Email 2FA",
    //        $"Your 2FA code is: {token}. Enter this code to enable Email 2FA.");

    //    // ✅ Store the token in TempData to pass it to the next request safely
    //    TempData["Email2FAToken"] = token;

    //    // ✅ Redirect to a new page: "ConfirmEnableEmail2FA"
    //    return RedirectToAction("ConfirmEnableEmail2FA");
    //}


    [HttpGet]
    [Authorize]
    public IActionResult ConfirmEnableEmail2FA(string userId, string token)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
        {
            _logger.LogWarning("❌ Missing userId or token in ConfirmEnableEmail2FA.");
            return RedirectToAction("Manage2FA");
        }

        _logger.LogInformation("✅ ConfirmEnableEmail2FA page loaded for user: {UserId}", userId);

        var model = new ConfirmEnableEmail2FAViewModel
        {
            UserId = userId,
            Token = token
        };

        return View(model);
    }

    [HttpPost]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ConfirmEnableEmail2FA(ConfirmEnableEmail2FAViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound("User not found.");
        }

        // ✅ Use the token from the model instead of TempData
        if (string.IsNullOrEmpty(model.Token))
        {
            _logger.LogWarning("❌ No token provided for verification.");
            return RedirectToAction("ConfirmEnableEmail2FA", new { userId = model.UserId });
        }

        // ✅ Verify the 2FA token
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", model.Code);
        if (!isValid)
        {
            _logger.LogWarning("❌ Invalid 2FA code entered.");
            ModelState.AddModelError("", "Invalid code. Please try again.");
            return View(model);
        }

        // ✅ Enable Email 2FA
        await _userManager.SetTwoFactorEnabledAsync(user, true);
        await _userManager.SetAuthenticationTokenAsync(user, "Email", "Email2FA", model.Token);

        _logger.LogInformation("✅ Email 2FA successfully enabled for user: {Email}", user.Email);
        return RedirectToAction("Manage2FA");
    }


    [HttpGet]
    public IActionResult VerifyEmail2FA(string userId)
    {
        _logger.LogInformation("🔍 VerifyEmail2FA page loaded for user: {UserId}", userId);

        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("❌ Missing userId in VerifyEmail2FA.");
            return View("Error");
        }

        var model = new VerifyEmail2FAModel { UserId = userId };
        return View(model); // ✅ Shows the page where the user enters the code
    }



    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyEmail2FA(VerifyEmail2FAModel model, string returnUrl = null)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var userId = HttpContext.Session.GetString("2FAUserId");
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("❌ No user ID found in session for 2FA verification.");
            return RedirectToAction("Login");
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogError("❌ Unable to find user with ID {UserId} for 2FA verification.", userId);
            return RedirectToAction("Login");
        }


        var isValidToken = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", model.Code);
        if (!isValidToken)
        {
            _logger.LogWarning("🚨 Invalid 2FA token entered by user: {Email}", user.Email);
            ModelState.AddModelError(string.Empty, "Invalid 2FA code.");
            return View(model);
        }

        if (isValidToken)
        {
            await _signInManager.SignInAsync(user, isPersistent: true);
            _logger.LogInformation("✅ User {Email} successfully signed in after 2FA.", user.Email);
            // ✅ Invalidate previous sessions
            var userSessions = _context.UserSessions.Where(us => us.UserId == user.Id && us.IsActive).ToList();
            foreach (var session in userSessions)
            {
                session.IsActive = false;
            }
            await _context.SaveChangesAsync();

            // ✅ Notify other sessions to logout
            await _hubContext.Clients.User(user.Id).SendAsync("Logout");

            // ✅ Create new session
            var newSession = new UserSession
            {
                UserId = user.Id,
                SessionId = HttpContext.Session.Id, // Ensures session is active
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };
            _context.UserSessions.Add(newSession);
            await _context.SaveChangesAsync();

            return RedirectToLocal(returnUrl);
        }
        else
        {
            ModelState.AddModelError(string.Empty, "Invalid 2FA code.");
            return View(model);
        }
    }





    [HttpGet]
    [Authorize]
    public async Task<IActionResult> Manage2FA()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        var model = new Manage2FAModel
        {
            TwoFactorEnable = user.TwoFactorEnabled,
            TwoFactorType = user.TwoFactorType
        };

        ViewBag.Message = TempData["Message"];
        return View(model);
    }


    [HttpGet]
    [Authorize]
    public async Task<IActionResult> EnableGoogleAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var qrCodeUri = GenerateQrCodeUri("BookWorms Online", user.Email, key);
        ViewBag.QrCodeUri = qrCodeUri;
        ViewBag.Key = key;

        return View();
    }


    // Ensure the following method is updated to use the correct QRCode class from QRCoder namespace
    private string GenerateQrCodeUri(string issuer, string email, string key)
    {
        var qrCodeUri = $"otpauth://totp/{issuer}:{email}?secret={key}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
        using (var qrGenerator = new QRCodeGenerator())
        {
            var qrCodeData = qrGenerator.CreateQrCode(qrCodeUri, QRCodeGenerator.ECCLevel.Q);
            using (var qrCode = new QRCoder.QRCode(qrCodeData)) // Ensure QRCode is from QRCoder namespace
            {
                using (var qrCodeImage = qrCode.GetGraphic(20))
                {
                    using (var ms = new MemoryStream())
                    {
                        qrCodeImage.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                        return $"data:image/png;base64,{Convert.ToBase64String(ms.ToArray())}";
                    }
                }
            }
        }
    }




    [HttpPost]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Manage2FA(Manage2FAModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        user.TwoFactorEnabled = model.TwoFactorEnable;
        user.TwoFactorType = model.TwoFactorType;
        await _userManager.UpdateAsync(user);

        ViewBag.Message = "Settings saved successfully.";

        if (model.TwoFactorType == "GoogleAuthenticator" && model.TwoFactorEnable)
        {
            return RedirectToAction("EnableGoogleAuthenticator");
        }
        else if (model.TwoFactorType == "Email" && model.TwoFactorEnable)
        {
            var code = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            await _emailSender.SendEmailAsync(user.Email, "Your 2FA Code", $"Your 2FA code is {code}");

            return RedirectToAction("ConfirmEnableEmail2FA", new { userId = user.Id, token = code });


        }

        return View(model);
    }





    [HttpPost]
    [Authorize]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login");
        }

        // Enforce minimum password age (e.g., 1 day)
        var minPasswordAge = TimeSpan.FromDays(1);
        if (DateTime.UtcNow - user.PasswordLastChanged < minPasswordAge)
        {
            ModelState.AddModelError(string.Empty, $"You cannot change your password within {minPasswordAge.TotalDays} days of the last change.");
            return View(model);
        }

        // Enforce maximum password age (e.g., 90 days)
        var maxPasswordAge = TimeSpan.FromDays(90);
        if (DateTime.UtcNow - user.PasswordLastChanged > maxPasswordAge)
        {
            ModelState.AddModelError(string.Empty, $"You must change your password every {maxPasswordAge.TotalDays} days.");
            return View(model);
        }

        // Check password history
        var passwordHasher = new PasswordHasher<ApplicationUser>();
        foreach (var passwordHistory in user.PasswordHistories.OrderByDescending(ph => ph.CreatedAt).Take(2))
        {
            if (passwordHasher.VerifyHashedPassword(user, passwordHistory.PasswordHash, model.NewPassword) != PasswordVerificationResult.Failed)
            {
                ModelState.AddModelError(string.Empty, "You cannot reuse your last 2 passwords.");
                return View(model);
            }
        }

        var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        if (result.Succeeded)
        {
            // Add new password to history
            user.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash,
                CreatedAt = DateTime.UtcNow
            });
            user.PasswordLastChanged = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            await _signInManager.RefreshSignInAsync(user);
            return RedirectToAction("ChangePasswordConfirmation");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(model);
    }



    public IActionResult ChangePasswordConfirmation()
    {
        return View();
    }


    //[HttpGet]
    //public IActionResult ForgotPassword()
    //{
    //    return View();
    //}

    //[HttpPost]
    //[ValidateAntiForgeryToken]
    //public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    //{
    //    var ipAddress = HttpContext.Connection.RemoteIpAddress.ToString();
    //    var delay = _exponentialBackoffService.GetDelay(ipAddress);
    //    await Task.Delay(delay * 1000);

    //    if (!string.IsNullOrEmpty(model.Honeypot))
    //    {
    //        return BadRequest("Invalid request.");
    //    }

    //    if (!ModelState.IsValid)
    //    {
    //        _exponentialBackoffService.Reset(ipAddress);
    //        return View(model);
    //    }

    //    var recaptchaResult = await _recaptchaService.Validate(Request);
    //    if (!recaptchaResult.success)
    //    {
    //        ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
    //        return View(model);
    //    }

    //    var user = await _userManager.FindByEmailAsync(model.Email);
    //    if (user == null)
    //    {
    //        return RedirectToAction(nameof(ForgotPasswordConfirmation));
    //    }

    //    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
    //    var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { token, email = user.Email }, protocol: HttpContext.Request.Scheme);
    //    await _emailSender.SendEmailAsync(model.Email, "Reset Password", $"Please reset your password by <a href='{callbackUrl}'>clicking here</a>.");

    //    _exponentialBackoffService.Reset(ipAddress);
    //    return RedirectToAction(nameof(ForgotPasswordConfirmation));
    //}

    [HttpGet]
    public IActionResult ForgotPassword()
    {
        return View();
    }
    [HttpPost]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
        _logger.LogInformation("ForgotPassword POST request received.");

        if (!ModelState.IsValid)
        {
            _logger.LogWarning("ForgotPassword model state is invalid. Errors: {Errors}",
                ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage));
            return View(model);
        }

        // Find the user by email
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            _logger.LogWarning("User with email {Email} not found.", model.Email);
            return View("ForgotPasswordConfirmation");
        }

        // Generate password reset token
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var callbackUrl = Url.Action("ResetPassword", "Account", new { token, email = user.Email }, protocol: HttpContext.Request.Scheme);

        _logger.LogInformation("Password reset link for {Email}: {Url}", model.Email, callbackUrl);

        _logger.LogInformation("Sending password reset email to {Email}.", model.Email);

        await _emailSender.SendEmailAsync(model.Email, "Reset Password",
            $"Please reset your password by <a href='{callbackUrl}'>clicking here</a>.");

        _logger.LogInformation("Password reset email sent to {Email}.", model.Email);

        return View("ForgotPasswordConfirmation");
    }



    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }


    [HttpGet]
    public IActionResult ResetPassword(string token = null)
    {
        if (token == null)
        {
            throw new ApplicationException("A code must be supplied for password reset.");
        }
        return View(new ResetPasswordViewModel { Token = token });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("ResetPassword model state is invalid. Errors: {Errors}",
                ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage));
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            _logger.LogWarning("User with email {Email} not found.", model.Email);
            // Don't reveal that the user does not exist
            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }

        var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
        if (result.Succeeded)
        {
            _logger.LogInformation("Password reset successful for user {Email}.", model.Email);
            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }

        foreach (var error in result.Errors)
        {
            _logger.LogError("Error resetting password for user {Email}: {Error}", model.Email, error.Description);
            ModelState.AddModelError(string.Empty, error.Description);
        }
        return View(model);
    }

    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }



    private IActionResult RedirectToLocal(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return RedirectToAction(nameof(HomeController.Index), "Home");
    }

    private async Task<bool> IsReCaptchaValid(string token)
    {
        var secretKey = _configuration["Recaptcha:SecretKey"];
        var client = new HttpClient();
        var requestUrl = $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}";

        _logger.LogInformation("Sending reCAPTCHA validation request to URL: {Url}", requestUrl);
        _logger.LogInformation("reCAPTCHA request payload: secret={SecretKey}, response={Token}", secretKey, token);

        var response = await client.PostAsync(requestUrl, null);
        var jsonString = await response.Content.ReadAsStringAsync();

        _logger.LogInformation("reCAPTCHA response: {Response}", jsonString); // Log the response

        dynamic jsonData = JsonConvert.DeserializeObject(jsonString);
        return jsonData.success == "true";
    }

}
