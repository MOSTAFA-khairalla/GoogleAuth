using GoogleAuth.Models;
using Microsoft.EntityFrameworkCore;

namespace GoogleAuth.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<ApplicationUser> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Make email unique
            modelBuilder.Entity<ApplicationUser>()
                .HasIndex(u => u.Email)
                .IsUnique();

            // Make PasswordHash nullable
            modelBuilder.Entity<ApplicationUser>()
                .Property(u => u.PasswordHash)
                .IsRequired(false);
        }
    }
}
