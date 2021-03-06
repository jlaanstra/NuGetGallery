﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NuGetGallery.FunctionTests.Helpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAutomation;

namespace NuGetGallery.FunctionalTests.Fluent
{

    [TestClass]
    public class ErrorPageTest : NuGetFluentTest
    {

        [TestMethod]
        [Description("Validate the 500 and 404 error pages.")]
        public void ErrorPage()
        {
            // Verify the 500 error page's text.
            I.Open(UrlHelper.BaseUrl + "/Errors/500?aspxerrorpath=/packages");
            I.Expect.Count(1).Of("h1:contains('Oh no, we broke something!')");
            I.Expect.Count(0).Of("h1:contains('Page Not Found')");

            // Verify the 404 error page's text.
            I.Open(UrlHelper.BaseUrl + "/ThisIsNotAMeaningfulUrl");
            I.Expect.Count(0).Of("h1:contains('Oh no, we broke something!')");
            I.Expect.Count(1).Of("h1:contains('Page Not Found')");

            // Search from the 404 page, verify result.
            I.Click("#searchBoxSubmit");
            I.Expect.Url(x => x.AbsoluteUri.Contains("/packages?q=ThisIsNotAMeaningfulUrl"));
        }
    }
}
