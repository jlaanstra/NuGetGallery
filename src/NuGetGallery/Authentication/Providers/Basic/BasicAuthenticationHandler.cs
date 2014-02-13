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

        protected AuthenticationService Auth { get; set; }

        public BasicAuthenticationHandler(ILogger logger, AuthenticationService auth)
        {
            this.logger = logger;
            this.Auth = auth;
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            logger.WriteVerbose("ApplyResponseChallenge");
            if (Response.StatusCode == 401 && (Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode) != null))
            {
                Response.Headers.Append("WWW-Authenticate", "Basic realm=Methylium NuGet");
            }
            else
            {
                await base.ApplyResponseChallengeAsync();
            }
        }
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            logger.WriteVerbose("AuthenticateCore");
            
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
                        var user = await Auth.Authenticate(parts[0], parts[1]);
                        if(user == null)
                        {
                            return null;
                        }
                        Context.Set(Constants.CurrentUserOwinEnvironmentKey, user);
                        var identity = AuthenticationService.CreateIdentity(user.User, AuthenticationTypes.LocalUser);
                        return new AuthenticationTicket(identity, new AuthenticationProperties());
                    }
                }
            }

            return null;
        }
    }
}