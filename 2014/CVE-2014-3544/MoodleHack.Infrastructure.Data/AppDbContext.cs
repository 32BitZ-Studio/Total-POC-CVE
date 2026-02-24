using Microsoft.EntityFrameworkCore;
using MoodleHack.Domain.Entities;

namespace MoodleHack.Infrastructure.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext() : base()
        { }

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        { }
        public DbSet<RequestEntity> Requests { get; protected set; }
        public DbSet<UserAccountEntity> Users { get; protected set; }
        
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<RequestEntity>().HasKey(x => x.Id);
            modelBuilder.Entity<RequestEntity>().HasIndex(x => x.Created);
            modelBuilder.Entity<RequestEntity>().HasIndex(x => x.Ip);
            modelBuilder.Entity<RequestEntity>().HasIndex(x => x.Request);
            modelBuilder.Entity<RequestEntity>().HasIndex(x => x.Success);

            modelBuilder.Entity<UserAccountEntity>().HasKey(x => x.Id);
            modelBuilder.Entity<UserAccountEntity>().HasIndex(x => x.Cookie);
            modelBuilder.Entity<UserAccountEntity>().HasIndex(x => x.Created);
            modelBuilder.Entity<UserAccountEntity>().HasIndex(x => x.Fio);
            modelBuilder.Entity<UserAccountEntity>().HasIndex(x => x.Role);
            modelBuilder.Entity<UserAccountEntity>().HasIndex(x => x.IsActive);
            base.OnModelCreating(modelBuilder);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseNpgsql("User ID=postgres;Password=root;Server=localhost;Port=5432;Database=moodle-database;Integrated Security=true;");
            }
            base.OnConfiguring(optionsBuilder);
        }
    }
}