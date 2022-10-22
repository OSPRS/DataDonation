using Microsoft.EntityFrameworkCore;
namespace DB
{
    public class DatabaseContext : DbContext
    {
        public DatabaseContext(DbContextOptions options) : base(options)
        {
        }
        public DbSet<Models.DataDonationEntry> DataDonationEntries { get; set; }

    }
}