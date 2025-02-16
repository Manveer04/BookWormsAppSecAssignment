using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookWorms.Views.Account
{
    public class EnableEmail2FAModel : PageModel
    {
        [BindProperty]
        public string UserId { get; set; }

        public void OnGet(string userId)
        {
            UserId = userId;
        }
    }
}

