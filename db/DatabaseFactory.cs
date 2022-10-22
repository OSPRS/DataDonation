

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using System;

namespace DB
{
    public class DatabaseContextFactory : IDesignTimeDbContextFactory<DatabaseContext>
    {
        public DatabaseContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<DatabaseContext>();
            optionsBuilder.UseMySql("server=localhost;database=datadonation;user=root;password=example;OldGuids=true", new MySqlServerVersion(new Version(8, 0, 29)));

            return new DatabaseContext(optionsBuilder.Options);
        }
    }
}
