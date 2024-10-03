using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using AuthXSSOServiceProvider.Saml.Schemas;

namespace AuthXSSOServiceProvider.Saml.MvcCore.Configuration
{
    public static class SamlServiceCollectionExtensions
    {
        public static IServiceCollection AddSaml(this IServiceCollection services, string loginPath = "/Auth/Login", bool slidingExpiration = false, string accessDeniedPath = null, ITicketStore sessionStore = null, SameSiteMode cookieSameSite = SameSiteMode.Lax, string cookieDomain = null, CookieSecurePolicy cookieSecurePolicy = CookieSecurePolicy.SameAsRequest)
        {
            services.AddAuthentication(SamlConstants.AuthenticationScheme)
                .AddCookie(SamlConstants.AuthenticationScheme, o =>
                {
                    o.LoginPath = new PathString(loginPath);
                    o.SlidingExpiration = slidingExpiration;
                    if (!string.IsNullOrEmpty(accessDeniedPath))
                    {
                        o.AccessDeniedPath = new PathString(accessDeniedPath);
                    }
                    if (sessionStore != null)
                    {
                        o.SessionStore = sessionStore;
                    }
                    o.Cookie.SameSite = cookieSameSite;
                    o.Cookie.SecurePolicy = cookieSecurePolicy;
                    if (!string.IsNullOrEmpty(cookieDomain))
                    {
                        o.Cookie.Domain = cookieDomain;
                    }
                });

            return services;
        }   
    }
}
