using BookWorms.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace BookWorms.Controllers
{
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Identity;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authorization;
    using Ganss.Xss;

    public class HomeController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly HtmlSanitizer _htmlSanitizer;

        public HomeController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
            _htmlSanitizer = new HtmlSanitizer();
        }

        public async Task<IActionResult> Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Home");
            }
            return View("Index"); // Show Index.cshtml for non-logged-in users
        }

        [Authorize]
        public async Task<IActionResult> Home()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction("Index"); // If somehow user data is missing, return to Index
            }

            var model = new UserProfileViewModel
            {
                FirstName = _htmlSanitizer.Sanitize(user.FirstName),
                LastName = _htmlSanitizer.Sanitize(user.LastName),
                CreditCardNo = _htmlSanitizer.Sanitize(user.CreditCardNo),
                BillingAddress = _htmlSanitizer.Sanitize(user.BillingAddress),
                ShippingAddress = _htmlSanitizer.Sanitize(user.ShippingAddress),
                Email = _htmlSanitizer.Sanitize(user.Email),
                MobileNo = _htmlSanitizer.Sanitize(user.MobileNo),
                PhotoPath = _htmlSanitizer.Sanitize(user.PhotoPath)
            };

            return View("Home", model); // Show Home.cshtml for logged-in users
        }

        public IActionResult Error404()
        {
            return View("Error404");
        }

        public IActionResult Error403()
        {
            return View("Error403");
        }
    }

}

