using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using MongoDB.Driver;
using MongoDB.EntityFrameworkCore.Extensions;

namespace DataAccess
{
    public class LPSSecurityDbContext : DbContext
    {
        public LPSSecurityDbContext(DbContextOptions<LPSSecurityDbContext> options) : base(options) { }

        public DbSet<User> User { get; init; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<User>().ToCollection("user");
        }
    }
}