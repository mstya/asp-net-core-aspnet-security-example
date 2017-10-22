using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;

using Microsoft.AspNetCore.Authentication;

namespace AspNetSecurityIntro
{
    public class AuthorizationProvider : OpenIdConnectServerProvider
    {
        public override Task HandleTokenRequest(HandleTokenRequestContext context)
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
        }

        public override Task ValidateTokenRequest(ValidateTokenRequestContext context)
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
        }

        public override Task ValidateIntrospectionRequest(ValidateIntrospectionRequestContext context)
        {
            if (string.Equals(context.ClientId, "client_id", StringComparison.Ordinal) &&
                string.Equals(context.ClientSecret, "client_secret", StringComparison.Ordinal))
            {
                context.Validate();
            }

            return Task.CompletedTask;
        }
    }
}