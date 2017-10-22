using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AspNetSecurityIntro.Controllers
{
    public class AuthorizationController : Controller
    {
        [Authorize, HttpGet("~/connect/token")]
        public Task GetAccessToken(HandleTokenRequestContext context, CancellationToken cancellationToken)
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
    }
}