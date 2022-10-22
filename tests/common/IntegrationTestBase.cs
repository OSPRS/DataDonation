using DB;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Xunit;
using Xunit.Abstractions;
using Serilog.Events;
using Microsoft.EntityFrameworkCore;
using API;

public class IntegrationTestBase : IClassFixture<IntegrationTestFactory<Program, DatabaseContext>>
{
    public readonly IntegrationTestFactory<Program, DatabaseContext> Factory;
    public readonly DatabaseContext DbContext;

    public ILogger _output;

    public IntegrationTestBase(IntegrationTestFactory<Program, DatabaseContext> factory, ITestOutputHelper output)
    {
        // Pass the ITestOutputHelper object to the TestOutput sink
        _output = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .WriteTo.TestOutput(output, LogEventLevel.Verbose)
            .CreateLogger()
            .ForContext<IntegrationTestBase>();
        Log.Logger = _output;

        Factory = factory;
        var scope = factory.Services.CreateScope();
        DbContext = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        DbContext.Database.Migrate();


    }
}