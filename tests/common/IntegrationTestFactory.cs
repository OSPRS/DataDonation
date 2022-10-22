using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

public class IntegrationTestFactory<TProgram, TDbContext> : WebApplicationFactory<TProgram>, IAsyncLifetime
    where TProgram : class where TDbContext : DbContext
{
    private readonly TestcontainerDatabase _container;

    public IntegrationTestFactory()
    {
        _container = new TestcontainersBuilder<MySqlTestcontainer>()
            .WithDatabase(new MySqlTestcontainerConfiguration { Database = "datadonation", Username = "test123", Password = "example"})
            .WithEnvironment("MYSQL_ROOT_PASSWORD", "example")
            .WithImage("mysql:8.0.29")
            .WithCleanUp(true)
            .Build();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureTestServices(services =>
        {
            // Remove previous DbContext
            var context = services.FirstOrDefault(descriptor => descriptor.ServiceType == typeof(TDbContext));
            if (context != null)
            {
                services.Remove(context);
                var options = services.Where(r => (r.ServiceType == typeof(DbContextOptions))
                  || (r.ServiceType.IsGenericType && r.ServiceType.GetGenericTypeDefinition() == typeof(DbContextOptions<>))).ToArray();
                foreach (var option in options)
                {
                    services.Remove(option);
                }
            }

            var connectionString = _container.ConnectionString.Replace("test123", "root") + ";OldGuids=true" ;

            var serverVersion =
                new MySqlServerVersion(ServerVersion.AutoDetect(connectionString));
            services.AddDbContext<TDbContext>(options => { options.UseMySql(connectionString, serverVersion); });
        });
    }

    public async Task InitializeAsync() => await _container.StartAsync();

    public new async Task DisposeAsync() => await _container.DisposeAsync();
}