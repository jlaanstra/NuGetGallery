using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace NuGetGallery.Authentication.Providers.Basic
{
    public class BasicAuthenticationMiddleware : AuthenticationMiddleware<BasicAuthenticationOptions>
    {
        private readonly ILogger logger;

        public BasicAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, BasicAuthenticationOptions options)
            : base(next, options)
        {
            logger = app.CreateLogger<BasicAuthenticationMiddleware>();
        }

        protected override AuthenticationHandler<BasicAuthenticationOptions> CreateHandler()
        {
            return new BasicAuthenticationHandler(this.logger);
        }
    }
}