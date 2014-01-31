using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace NuGetGallery.Authentication.Providers.Basic
{
    public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        private readonly ILogger logger;

        public BasicAuthenticationHandler(ILogger logger)
        {
            this.logger = logger;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            logger.WriteVerbose("ApplyResponseChallenge");
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                Response.Headers.Set("WWW-Authenticate", "Basic realm=Methylium NuGet");
            }

            return Task.FromResult<object>(null);
        }
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            logger.WriteVerbose("AuthenticateCore");

            AuthenticationProperties properties = null;

            var header = Request.Headers["Authorization"];

            if (!String.IsNullOrWhiteSpace(header))
            {
                var authHeader = AuthenticationHeaderValue.Parse(header);

                if ("Basic".Equals(authHeader.Scheme, StringComparison.OrdinalIgnoreCase))
                {
                    string parameter = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter));
                    var parts = parameter.Split(':');
                    if (parts.Length == 2)
                    {
                        var user = await Options.AuthenticationService.Authenticate(parts[0], parts[1]);
                        var identity = AuthenticationService.CreateIdentity(user.User, AuthenticationTypes.LocalUser);
                        return new AuthenticationTicket(identity, properties);
                    }
                }
            }

            return null;
        }
    }
}