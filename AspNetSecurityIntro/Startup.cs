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
                options.SystemClock = new SystemClock();
                options.TokenEndpointPath = "/connect/token";
                options.IntrospectionEndpointPath = "/connect/introspect";
                options.AllowInsecureHttp = true;
                options.AccessTokenLifetime = TimeSpan.FromDays(365);
                
                options.Issuer = new Uri("http://localhost:64855");
                options.ApplicationCanDisplayErrors = true;

                options.Provider.OnValidateIntrospectionRequest = context =>
                {
                    if (string.Equals(context.ClientId, "client_id", StringComparison.Ordinal) &&
                        string.Equals(context.ClientSecret, "client_secret", StringComparison.Ordinal))
                    {
                        context.Validate();
                    }

                    return Task.CompletedTask;
                };

                options.Provider.OnValidateTokenRequest = context =>
                {
                    // Reject token requests that don't use grant_type=password or grant_type=refresh_token.
                    if (!context.Request.IsPasswordGrantType() && !context.Request.IsRefreshTokenGrantType())
                    {
                        context.Reject(
                            error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                            description: "Only grant_type=password and refresh_token " +
                                         "requests are accepted by this server.");

                        return Task.CompletedTask;
                    }

                    if (string.Equals(context.ClientId, "client_id", StringComparison.Ordinal) &&
                        string.Equals(context.ClientSecret, "client_secret", StringComparison.Ordinal))
                    {
                        context.Validate();
                    }

                    return Task.CompletedTask;
                };

                options.Provider.OnHandleTokenRequest = context =>
                {
                    if (context.Request.IsPasswordGrantType())
                    {
                        if (!string.Equals(context.Request.Username, "Bob", StringComparison.Ordinal) ||
                            !string.Equals(context.Request.Password, "P@ssw0rd", StringComparison.Ordinal))
                        {
                            context.Reject(
                                error: OpenIdConnectConstants.Errors.InvalidGrant,
                                description: "Invalid user credentials.");

                            return Task.CompletedTask;
                        }

                        var identity = new ClaimsIdentity(context.Scheme.Name,
                            OpenIdConnectConstants.Claims.Name,
                            OpenIdConnectConstants.Claims.Role);
                        
                        identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "[unique id]", OpenIdConnectConstants.Destinations.IdentityToken);

                        identity.AddClaim("urn:customclaim", "value",
                            OpenIdConnectConstants.Destinations.AccessToken,
                            OpenIdConnectConstants.Destinations.IdentityToken);
                        
                        var ticket = new AuthenticationTicket(
                            new ClaimsPrincipal(identity),
                            new AuthenticationProperties(),
                            context.Scheme.Name);
                        ticket.SetResources("resource_server");
                        ticket.SetScopes(
                            OpenIdConnectConstants.Scopes.Profile,
                            OpenIdConnectConstants.Scopes.OfflineAccess
                            );

                        context.Validate(ticket);
                    }

                    return Task.CompletedTask;
                };
            });

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
