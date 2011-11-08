﻿#pragma warning disable 1591
//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.239
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace NuGetGallery.Views.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Text;
    using System.Web;
    using System.Web.Helpers;
    using System.Web.Mvc;
    using System.Web.Mvc.Ajax;
    using System.Web.Mvc.Html;
    using System.Web.Routing;
    using System.Web.Security;
    using System.Web.UI;
    using System.Web.WebPages;
    using Microsoft.Web.Helpers;
    
    #line 1 "..\..\Views\Shared\Layout.cshtml"
    using NuGetGallery;
    
    #line default
    #line hidden
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("RazorGenerator", "1.2.0.0")]
    [System.Web.WebPages.PageVirtualPathAttribute("~/Views/Shared/Layout.cshtml")]
    public class Layout : System.Web.Mvc.WebViewPage<dynamic>
    {
        public Layout()
        {
        }
        public override void Execute()
        {

WriteLiteral("<!DOCTYPE html> \r\n<html lang=\"en\" class=\"static \"> \r\n    <head>\r\n        <meta ch" +
"arset=\"utf-8\" />\r\n        <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\" /" +
">\r\n        <title>NuGet Gallery</title> \r\n        <link href=\"");


            
            #line 8 "..\..\Views\Shared\Layout.cshtml"
               Write(Url.Content("~/Content/site.css"));

            
            #line default
            #line hidden
WriteLiteral("\" rel=\"stylesheet\" />\r\n        <link href=\"");


            
            #line 9 "..\..\Views\Shared\Layout.cshtml"
               Write(Url.Content("~/Content/nuget.ico"));

            
            #line default
            #line hidden
WriteLiteral("\" rel=\"shortcut icon\" type=\"image/x-icon\" />\r\n        <script src=\"");


            
            #line 10 "..\..\Views\Shared\Layout.cshtml"
                Write(Url.Content("~/Scripts/modernizr-2.0.6-development-only.js"));

            
            #line default
            #line hidden
WriteLiteral("\"></script>\r\n        ");


            
            #line 11 "..\..\Views\Shared\Layout.cshtml"
   Write(MvcMiniProfiler.MiniProfiler.RenderIncludes());

            
            #line default
            #line hidden
WriteLiteral("\r\n    </head>\r\n    <body>\r\n        <div id=\"content-wraper\">\r\n            <header" +
" class=\"main\">\r\n                <div id=\"logo\"><a href=\"");


            
            #line 16 "..\..\Views\Shared\Layout.cshtml"
                                   Write(Url.Home());

            
            #line default
            #line hidden
WriteLiteral("\">NuGet Gallery</a></div>\r\n                ");


            
            #line 17 "..\..\Views\Shared\Layout.cshtml"
           Write(Html.Partial(MVC.Shared.Views.UserDisplay));

            
            #line default
            #line hidden
WriteLiteral("\r\n            </header>\r\n            <nav class=\"main\">\r\n                <ul id=\"" +
"menu\">\r\n");


            
            #line 21 "..\..\Views\Shared\Layout.cshtml"
                      
                        var homeClass = ViewBag.Tab == "Home" ? "current" : "";
                        var packagesClass = ViewBag.Tab == "Packages" ? "current" : "";
                        var uploadClass = ViewBag.Tab == "Upload" ? "current" : "";
                    

            
            #line default
            #line hidden
WriteLiteral("                    <li class=\"");


            
            #line 26 "..\..\Views\Shared\Layout.cshtml"
                          Write(homeClass);

            
            #line default
            #line hidden
WriteLiteral("\"><a href=\"");


            
            #line 26 "..\..\Views\Shared\Layout.cshtml"
                                               Write(Url.Home());

            
            #line default
            #line hidden
WriteLiteral("\">Home</a></li>\r\n                    <li class=\"");


            
            #line 27 "..\..\Views\Shared\Layout.cshtml"
                          Write(packagesClass);

            
            #line default
            #line hidden
WriteLiteral("\"><a href=\"");


            
            #line 27 "..\..\Views\Shared\Layout.cshtml"
                                                   Write(Url.PackageList());

            
            #line default
            #line hidden
WriteLiteral("\">Packages</a></li>\r\n                    <li class=\"");


            
            #line 28 "..\..\Views\Shared\Layout.cshtml"
                          Write(uploadClass);

            
            #line default
            #line hidden
WriteLiteral("\"><a href=\"");


            
            #line 28 "..\..\Views\Shared\Layout.cshtml"
                                                 Write(Url.UploadPackage());

            
            #line default
            #line hidden
WriteLiteral("\" class=\"upload\">Upload Package</a></li>\r\n                    <li><a href=\"http:/" +
"/docs.nuget.org\">Documentation</a></li>\r\n                </ul>\r\n                " +
"<div id=\"searchBox\">\r\n                    <form action=\"");


            
            #line 32 "..\..\Views\Shared\Layout.cshtml"
                             Write(Url.PackageList());

            
            #line default
            #line hidden
WriteLiteral("\" method=\"get\">\r\n                        <input name=\"q\" id=\"searchBoxInput\" plac" +
"eholder=\"Search Packages\" value=\"");


            
            #line 33 "..\..\Views\Shared\Layout.cshtml"
                                                                                             Write(String.IsNullOrEmpty(ViewBag.SearchTerm) ? "" : ViewBag.SearchTerm);

            
            #line default
            #line hidden
WriteLiteral("\" />\r\n                        <input id=\"searchBoxSubmit\" type=\"submit\" value=\" \"" +
" />\r\n                        <input type=\"hidden\" name=\"sortOrder\" value=\"");


            
            #line 35 "..\..\Views\Shared\Layout.cshtml"
                                                                Write(Const.DefaultPackageListSortOrder);

            
            #line default
            #line hidden
WriteLiteral("\" />\r\n                    </form>\r\n                </div>\r\n            </nav>\r\n  " +
"          <div id=\"body\">\r\n");


            
            #line 40 "..\..\Views\Shared\Layout.cshtml"
             if (TempData.ContainsKey("Message")) {

            
            #line default
            #line hidden
WriteLiteral("                <p class=\"message\">");


            
            #line 41 "..\..\Views\Shared\Layout.cshtml"
                              Write(TempData["Message"]);

            
            #line default
            #line hidden
WriteLiteral("</p>\r\n");


            
            #line 42 "..\..\Views\Shared\Layout.cshtml"
            }

            
            #line default
            #line hidden
WriteLiteral("            ");


            
            #line 43 "..\..\Views\Shared\Layout.cshtml"
       Write(RenderBody());

            
            #line default
            #line hidden
WriteLiteral(@"
            </div>
        </div>
        <div id=""layout-footer"" class=""group"">
            <footer id=""footer"">
                <ul class=""recommended"">
                    <li>
                        <a href=""http://docs.nuget.org/docs/start-here/overview"">Overview</a>
                        <p>NuGet is a Visual Studio 2010 extension that makes it easy to add, remove, and update libraries and...</p>
                    </li>
                    <li>
                        <a href=""http://docs.nuget.org/docs/start-here/installing-nuget"">Install</a>
                        <p>NuGet can be installed and updated using the Visual Studio Extension Manager. To check if your copy...</p>
                    </li>
                    <li>
                        <a href=""http://docs.nuget.org/docs/start-here/videos"">Videos</a>
                        <p>Watch screencasts and presentations about anything and everything NuGet.</p>
                    </li>
                    <li>
                        <a href=""http://docs.nuget.org/docs/start-here/nuget-faq"">FAQ</a>
                        <p>Read the Frequently Asked Questions about NuGet and see if your question made the list.</p>
                    </li>
                </ul>
                <div class=""license"">
                    <p>
                        &copy; ");


            
            #line 68 "..\..\Views\Shared\Layout.cshtml"
                          Write(DateTime.UtcNow.Year);

            
            #line default
            #line hidden
WriteLiteral(" Outercurve Foundation.\r\n                    </p>\r\n                </div>\r\n      " +
"      </footer>\r\n        </div>\r\n        <script src=\"");


            
            #line 73 "..\..\Views\Shared\Layout.cshtml"
                Write(Url.Content("~/Scripts/jquery-1.6.2.min.js"));

            
            #line default
            #line hidden
WriteLiteral("\"></script>\r\n        ");


            
            #line 74 "..\..\Views\Shared\Layout.cshtml"
   Write(RenderSection("BottomScripts", required: false));

            
            #line default
            #line hidden
WriteLiteral("\r\n    </body>\r\n</html>");


        }
    }
}
#pragma warning restore 1591
