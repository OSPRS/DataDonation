using Microsoft.EntityFrameworkCore;
namespace DataDonation.Database
{
    public class DatabaseContext : DbContext
    {
        public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options)
        {
        }
        public DbSet<Models.DataDonationEntry> DataDonationEntries { get; set; }

    }
}