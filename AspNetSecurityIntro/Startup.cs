using System;
using System.Security.Claims;
using System.Threading.Tasks;

using AspNet.Security.OAuth.Validation;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetSecurityIntro
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            this.Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(
                    options =>
                    {
                       
                        options.DefaultAuthenticateScheme = OAuthValidationDefaults.AuthenticationScheme;
                    })
                .AddOAuthValidation(
                    options =>
                    {
                        options.IncludeErrorDetails = true;
                        options.Audiences.Add("resource_server");
                    });

            services.AddAuthentication().AddOpenIdConnectServer(options =>
            {
                options.ProviderType = typeof(AuthorizationProvider);

                options.TokenEndpointPath = "/connect/token";
                options.IntrospectionEndpointPath = "/connect/introspect";
                options.AllowInsecureHttp = true;
                options.AccessTokenLifetime = TimeSpan.FromDays(365);
            });

            services.AddScoped<AuthorizationProvider>();

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
