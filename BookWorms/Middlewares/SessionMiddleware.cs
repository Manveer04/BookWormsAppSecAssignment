using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Threading.Tasks;

public class SessionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger _logger;

    public SessionMiddleware(RequestDelegate next, IServiceProvider serviceProvider, ILogger logger)
    {
        _next = next;
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        using (var scope = _serviceProvider.CreateScope())
        {
            var _context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            if (context.Session.IsAvailable && !context.Session.Keys.Contains("UserSession"))
            {
                context.Session.SetString("UserSession", "Active");
            }
            else if (context.Session.IsAvailable && context.Session.GetString("UserSession") == null)
            {
                if (!context.Request.Path.StartsWithSegments("/Account/Login"))
                {
                    context.Session.SetString("RedirectedByMiddleware", "true");
                    context.Response.Redirect("/Account/Login?reason=timeout");
                    return;
                }
            }

            if (context.User.Identity.IsAuthenticated)
            {
                var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
                var sessionId = context.Session.Id;

                // ✅ Ensure session is available before checking for user session
                if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(sessionId))
                {
                    var userSession = await _context.UserSessions.FirstOrDefaultAsync(us => us.UserId == userId && us.SessionId == sessionId && us.IsActive);

                    if (userSession == null)
                    {
                        _logger.LogWarning("⚠️ No active session found for user {UserId}, but they are authenticated.", userId);

                        // ✅ Allow users who just completed 2FA to continue
                        if (!context.Request.Path.StartsWithSegments("/Account/VerifyEmail2FA"))
                        {
                            context.Session.SetString("RedirectedByMiddleware", "true");
                            context.Response.Redirect("/Account/Login?reason=multiplelogin");
                            return;
                        }
                    }
                }
            }


            await _next(context);
        }
    }
}




