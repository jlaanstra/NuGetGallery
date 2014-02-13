using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin.Security;

namespace NuGetGallery.Authentication.Providers.Basic
{
    public class BasicAuthenticationOptions : AuthenticationOptions
    {
        public BasicAuthenticationOptions()
            : base(AuthenticationTypes.LocalUser) { }
    }
}