using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using BookWorms.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.UI.Services;
using reCAPTCHA.AspNetCore;
using Serilog;
//using BookWorms.Middlewares;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

// Add services to the container.
builder.Services.AddSingleton<TokenService>();
builder.Services.AddTransient<AccountService>();
builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddSingleton(new ExponentialBackoffService(initialDelayInSeconds: 2));

builder.Services.AddControllersWithViews();

builder.Services.AddRecaptcha(options =>
{
    options.SiteKey = "6LeP9bMqAAAAADLhzN4GKmC8m5PxNiL4yUdezIdh";
    options.SecretKey = "6LeP9bMqAAAAAOwTo1GWBeXw3dKVrL7O5fO4L_ce";
});

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(3); // Adjust the token lifespan as needed
});

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromMinutes(5); // Ensure the token expires in 5 minutes
});



// Add Identity services
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddDefaultTokenProviders()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
});

// Register ApplicationDbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedEmail = false; // Disable email confirmation requirement
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
});

// Configure cookie policy
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    // This lambda determines whether user consent for non-essential cookies is needed for a given request.
    options.CheckConsentNeeded = context => true;
    options.MinimumSameSitePolicy = SameSiteMode.None;
});

// Configure account lockout
builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;

});

// Add session services
builder.Services.AddDistributedMemoryCache(); // ✅ Needed for session storage in memory
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(60); // ✅ Session timeout set to 60 minutes
    options.Cookie.HttpOnly = true; // ✅ Prevents JavaScript access for security
    options.Cookie.IsEssential = true; // ✅ Ensures session is stored even if user rejects non-essential cookies
});

// Configure authentication cookie
builder.Services.ConfigureApplicationCookie(options =>
{
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30); // Set cookie expiration to match session timeout
    options.SlidingExpiration = true; // Enable sliding expiration
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddSignalR();
builder.Services.AddTransient<AuditLogService>();
builder.Services.AddRecaptcha(options =>
{
    options.SiteKey = builder.Configuration["Recaptcha:SiteKey"];
    options.SecretKey = builder.Configuration["Recaptcha:SecretKey"];
});

builder.Services.AddSingleton<TwilioService>();


builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddTransient<AccountController>();

// Build the app
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}


app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseCookiePolicy();

app.UseWebSockets();

app.UseSession();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapHub<NotificationHub>("/notificationHub");
});


app.Use(async (context, next) =>
{
    context.Response.Headers.Add("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ https://cdnjs.cloudflare.com; " +
        "connect-src 'self' " +
            "wss://localhost:44315 " +
            "ws://localhost:6123 " +
            "http://localhost:6123 " +
            "https://www.google.com " +
            "http://localhost:49991 " +
            "ws://localhost:49991 " +
            "wss://localhost:44333 " +
            "http://localhost:8032 " +
            "ws://localhost:8032 " +   // <-- Add this for WebSocket connections
            "wss://localhost:8032 " +  // <-- Add this for secure WebSocket connections
            "wss://localhost:44377/BookWorms/; " +
        "img-src 'self' data:; " +
        "frame-src 'self' https://www.google.com;");
    await next();
});




app.UseStatusCodePages(async context =>
{
    var response = context.HttpContext.Response;

    if (response.StatusCode == 404)
    {
        response.Redirect("/Home/Error404");
    }
    else if (response.StatusCode == 403)
    {
        response.Redirect("/Home/Error403");
    }
});

// Add Serilog request logging middleware
app.UseSerilogRequestLogging();


app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
