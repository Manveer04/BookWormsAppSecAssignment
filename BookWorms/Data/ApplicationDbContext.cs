using BookWorms.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using static ApplicationUser;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public DbSet<PasswordHistory> PasswordHistories { get; set; }

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<UserSession> UserSessions { get; set; }
    public DbSet<AuditLog> AuditLogs { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>().Property(u => u.CreditCardNo).HasMaxLength(256);
        builder.Entity<ApplicationUser>().Property(u => u.PasswordLastChanged).IsRequired();
        builder.Entity<ApplicationUser>().Property(u => u.TwoFactorEnabled).IsRequired();
        builder.Entity<ApplicationUser>().Property(u => u.TwoFactorType).HasMaxLength(50);
        builder.Entity<PasswordHistory>()
                .HasOne<ApplicationUser>()
                .WithMany(u => u.PasswordHistories)
                .HasForeignKey(ph => ph.UserId);
    }

    public async Task<List<UserSession>> GetUserSessionsAsync(string userId)
    {
        // Using parameterized query to prevent SQL injection
        return await UserSessions.FromSqlRaw("EXEC GetUserSessions @UserId", new SqlParameter("@UserId", userId)).ToListAsync();
    }
}


