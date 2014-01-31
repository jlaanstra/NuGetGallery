using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using NuGetGallery.Configuration;
using Owin;

namespace NuGetGallery.Authentication
{
    public class ForceSslAlwaysMiddleware : OwinMiddleware
    {
        private readonly ILogger _logger;
        public int SslPort { get; private set; }

        public ForceSslAlwaysMiddleware(OwinMiddleware next, IAppBuilder app, int sslPort)
            : base(next)
        {
            SslPort = sslPort;
            _logger = app.CreateLogger<ForceSslAlwaysMiddleware>();
        }

        public override async Task Invoke(IOwinContext context)
        {
            if (!context.Request.IsSecure)
            {
                // Presence of the cookie is all we care about, value is ignored
                context.Response.Redirect(new UriBuilder(context.Request.Uri)
                {
                    Scheme = Uri.UriSchemeHttps,
                    Port = SslPort
                }.Uri.AbsoluteUri);
            }
            else
            {
                // Invoke the rest of the pipeline
                await Next.Invoke(context);
            }
        }
    }
}

namespace Owin {
    using NuGetGallery.Authentication;

    public static class ForceSslAlwaysExtensions
    {
        public static IAppBuilder UseForceSslAlways(this IAppBuilder self)
        {
            return UseForceSslAlways(
                self,
                443);
        }

        public static IAppBuilder UseForceSslAlways(this IAppBuilder self, int sslPort)
        {
            return self.Use(typeof(ForceSslAlwaysMiddleware), self, sslPort);
        }
    }
}