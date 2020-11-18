using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(mercrediAuthentication.Startup))]
namespace mercrediAuthentication
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
