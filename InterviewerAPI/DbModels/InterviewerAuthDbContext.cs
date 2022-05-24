using Microsoft.EntityFrameworkCore;

namespace InterviewerAPI.DbModels
{
    public partial class InterviewerAuthDbContext : DbContext
    {
        private readonly string _connectionString;
        public InterviewerAuthDbContext(string connectionString)
        {
            _connectionString = connectionString;
        }

        public InterviewerAuthDbContext(DbContextOptions<InterviewerAuthDbContext> options)
            : base(options)
        {
        }

        public virtual DbSet<UsersAccount> UsersAccounts { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseSqlServer(_connectionString);
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UsersAccount>(entity =>
            {
                entity.HasKey(e => e.AccountGlobalIdentifier);

                entity.HasIndex(e => e.UserEmail, "UC_UsersAccounts")
                    .IsUnique();

                entity.Property(e => e.AccountGlobalIdentifier).HasDefaultValueSql("(newid())");

                entity.Property(e => e.DateOfProfileCreation).HasColumnType("datetime");

                entity.Property(e => e.Salt)
                    .HasMaxLength(36)
                    .IsUnicode(false)
                    .HasDefaultValueSql("(newid())");

                entity.Property(e => e.UserEmail)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                entity.Property(e => e.UserPassword)
                    .HasMaxLength(255)
                    .IsUnicode(false);
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
