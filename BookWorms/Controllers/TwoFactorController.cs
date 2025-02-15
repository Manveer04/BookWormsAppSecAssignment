using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using QRCoder;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;

public class TwoFactorController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public TwoFactorController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpGet]
    public async Task<IActionResult> Enable2FA()
    {
        var user = await _userManager.GetUserAsync(User);
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var qrCodeUri = GenerateQrCodeUri("BookWorms Online", user.Email, key);
        ViewBag.QrCodeUri = qrCodeUri;
        ViewBag.Key = key;

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Verify2FA(string code)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, false, false);

        if (result.Succeeded)
        {
            user.TwoFactorEnabled = true;
            await _userManager.UpdateAsync(user);
            return RedirectToAction("Index", "Home");
        }

        ModelState.AddModelError(string.Empty, "Invalid code.");
        return View("Enable2FA");
    }

    private string GenerateQrCodeUri(string issuer, string email, string key)
    {
        var qrCodeUri = $"otpauth://totp/{issuer}:{email}?secret={key}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
        using (var qrGenerator = new QRCodeGenerator())
        {
            var qrCodeData = qrGenerator.CreateQrCode(qrCodeUri, QRCodeGenerator.ECCLevel.Q);
            var qrCode = new QRCode(qrCodeData);
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
