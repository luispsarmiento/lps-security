using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace DataAccess
{
    public class LPSSecurityDbContext : DbContext
    {
        public LPSSecurityDbContext(DbContextOptions<LPSSecurityDbContext> options) : base(options) { }

        public DbSet<User> User { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.HasAutoscaleThroughput(1000);

            modelBuilder.Entity<User>().ToContainer(nameof(User)).HasPartitionKey(e => e.Id);
        }
    }
}