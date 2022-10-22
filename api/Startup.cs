using System;
using DB;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;

namespace API {
public class Startup {
  public Startup(IConfiguration configuration) {
    Configuration = configuration;
  }

  public IConfiguration Configuration { get; }
  
        // This method gets called by the runtime. Use this method to add services to
  // the container.
  public void ConfigureServices(IServiceCollection services) {
    var connectionString =
        Configuration.GetConnectionString("DefaultConnection");
    Serilog.Log.Information(connectionString);
    var serverVersion = new MySqlServerVersion(new Version(8, 0, 29));


    try
    {
        serverVersion =
            new MySqlServerVersion(ServerVersion.AutoDetect(connectionString));

    }
    catch (Exception) { 
        // do nothing, it will crash later...
    }
    services.AddDbContext<DatabaseContext>(
        options => options.UseMySql(connectionString, serverVersion));

    services.AddControllers(); services.AddSwaggerGen(c => {
      c.SwaggerDoc("v1",
                   new OpenApiInfo { Title = "DataDonation", Version = "v1" });
    });
  }

  // This method gets called by the runtime. Use this method to configure the
  // HTTP request pipeline.
  public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
    if (env.IsDevelopment()) {
      app.UseDeveloperExceptionPage();
      app.UseSwagger();
      app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json",
                                              "DataDonation v1"));
    }

    // app.UseHttpsRedirection();

    app.UseRouting();

    app.UseAuthorization();

    app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
  }
}
}
