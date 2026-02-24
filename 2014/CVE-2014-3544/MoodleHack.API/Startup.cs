using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MoodleHack.API.Services;
using MoodleHack.Infrastructure.Data;

namespace MoodleHack.API
{
    public class Startup
    {
        private IConfiguration _configuration;
        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<AppDbContext>(x =>
                x.UseNpgsql(_configuration["POSTGRESQL"],
                    npgsql => npgsql.MigrationsAssembly(nameof(MoodleHack.Infrastructure.Data))));
            services.Configure<EmailConfiguration>(_configuration.GetSection("MAIL"));
            services.AddScoped<SdoApiClient>();
            services.AddScoped<EmailClient>();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            
            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}