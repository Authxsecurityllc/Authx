using AuthXSSOServiceProvider.Saml;
using AuthXSSOServiceProvider.Saml.Schemas;
using AuthXSSOServiceProvider.Saml.Mvc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Web.Mvc;
using System.Security.Claims;
using WebApplication.Identity;
using System.IdentityModel.Services;
using System.Security.Authentication;

namespace WebApplication.Controllers
{
    [AllowAnonymous]
    public class AuthController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly SamlConfiguration config;

        public AuthController()
        {
            config = IdentityConfig.SamlConfiguration;
        }

        public ActionResult Login(string returnUrl = null)
        {
            var binding = new SamlRedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new SamlAuthnRequest(config)
            {
            }).ToActionResult();
        }

        public ActionResult AssertionConsumerService()
        {
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            var SamlAuthnResponse = new SamlAuthnResponse(config);

            httpRequest.Binding.ReadSamlResponse(httpRequest, SamlAuthnResponse);
            if (SamlAuthnResponse.Status != SamlStatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {SamlAuthnResponse.Status}");
            }
            httpRequest.Binding.Unbind(httpRequest, SamlAuthnResponse);
            SamlAuthnResponse.CreateSession(claimsAuthenticationManager: new DefaultClaimsAuthenticationManager());

            var relayStateQuery = httpRequest.Binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }

        [ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new SamlPostBinding();
            //return binding.Bind(new SamlLogoutRequest(config, ClaimsPrincipal.Current)
            //{
            //}).ToActionResult();
            var logoutRequest = new SamlLogoutRequest(config, ClaimsPrincipal.Current).DeleteSession();
            return binding.Bind(logoutRequest).ToActionResult();
        }
        public ActionResult SingleLogout()
        {
            SamlStatusCodes status;
            var httpRequest = Request.ToGenericHttpRequest(validate: true);
            var logoutResponse = new SamlLogoutResponse(config);

            try
            {
                httpRequest.Binding.ReadSamlResponse(httpRequest, logoutResponse);
                if (logoutResponse.Status != SamlStatusCodes.Success)
                {
                    throw new AuthenticationException($"SAML Response status: {logoutResponse.Status}");
                }
                //httpRequest.Binding.Unbind(httpRequest, logoutResponse);
                status = SamlStatusCodes.Success;
                logoutResponse.DeleteSession();
                
            }
            catch (Exception exc)
            {
                // log exception
                Debug.WriteLine("SingleLogout error: " + exc.ToString());
                status = SamlStatusCodes.RequestDenied; //handle error
            }
            return Redirect(Url.Content("~/"));
           
        }
    }
}
