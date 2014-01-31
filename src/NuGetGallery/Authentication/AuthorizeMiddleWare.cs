using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;
using Owin;

namespace NuGetGallery.Authentication
{
    public class AuthorizeMiddleware : OwinMiddleware
    {
        public AuthorizeMiddleware(OwinMiddleware next, IAppBuilder app)
            : base(next) { }

        public override async Task Invoke(IOwinContext context)
        {
            if(!context.Request.User.Identity.IsAuthenticated)
            {
                context.Response.StatusCode = 401;
            }
            else
            {
                // Invoke the rest of the pipeline
                await Next.Invoke(context);
            }
        }
    }
}

namespace Owin
{
    using NuGetGallery.Authentication;

    public static class AuthorizeExtensions
    {
        public static IAppBuilder Authorize(this IAppBuilder self)
        {
            return self.Use(typeof(AuthorizeMiddleware), self);
        }
    }
}