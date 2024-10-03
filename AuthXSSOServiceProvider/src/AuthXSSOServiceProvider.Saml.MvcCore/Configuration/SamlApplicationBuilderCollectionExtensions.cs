using Microsoft.AspNetCore.Builder;

namespace AuthXSSOServiceProvider.Saml.MvcCore.Configuration
{
    public static class SamlApplicationBuilderCollectionExtensions
    {
        public static IApplicationBuilder UseSaml(this IApplicationBuilder app)
        {
            app.UseAuthentication();                       

            return app;
        }

    }
}
