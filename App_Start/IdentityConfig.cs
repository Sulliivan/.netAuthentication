using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using mercrediAuthentication.Models;
using SendGrid;
using SendGrid.Helpers.Mail;
using Twilio;
using Twilio.Rest.Api.V2010.Account;

namespace mercrediAuthentication
{
    public class EmailService : IIdentityMessageService
    {
        public async Task SendAsync(IdentityMessage message)
        {
            string key = @"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 ";
            var client = new SendGridClient(key);
            
            // Contenu
            var from = new EmailAddress("qraks-@hotmail.fr", "Application ASP");
            var subject = message.Subject;
            var to = new EmailAddress(message.Destination,"Nouveau utilisateur");
            var plainTextContent = message.Body;
            var htmlContent = message.Body;

            var email = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            await client.SendEmailAsync(email);

            // Indiquez votre service de messagerie ici pour envoyer un e-mail.
            // return Task.FromResult(0);
        }
    }

    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            const string accountSID = @"ACb11ed11b8a7c718f21726e5205fa7291";
            const string authToken = @"0e1a8b2f1532731698af7da00f4fa332";
            TwilioClient.Init(accountSID, authToken);

            // Contenu SMS
            var sms = MessageResource.Create(
                body: message.Body,
                from: new Twilio.Types.PhoneNumber("+16073036838"),
                to: new Twilio.Types.PhoneNumber(message.Destination)
                ) ;


            // Connectez votre service SMS ici pour envoyer un message texte.
            return Task.FromResult(0);
        }
    }

    // Configurer l'application que le gestionnaire des utilisateurs a utilisée dans cette application. UserManager est défini dans ASP.NET Identity et est utilisé par l'application.
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context) 
        {
            var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
            // Configurer la logique de validation pour les noms d'utilisateur
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configurer la logique de validation pour les mots de passe
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            // Configurer les valeurs par défaut du verrouillage de l'utilisateur
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Inscrire les fournisseurs d'authentification à 2 facteurs. Cette application utilise le téléphone et les e-mails comme procédure de réception de code pour confirmer l'utilisateur
            // Vous pouvez écrire votre propre fournisseur et le connecter ici.
            manager.RegisterTwoFactorProvider("Code téléphonique ", new PhoneNumberTokenProvider<ApplicationUser>
            {
                MessageFormat = "Votre code de sécurité est {0}"
            });
            manager.RegisterTwoFactorProvider("Code d'e-mail", new EmailTokenProvider<ApplicationUser>
            {
                Subject = "Code de sécurité",
                BodyFormat = "Votre code de sécurité est {0}"
            });
            manager.EmailService = new EmailService();
            manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = 
                    new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }

    // Configurer le gestionnaire de connexion d'application qui est utilisé dans cette application.
    public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
        {
            return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
        }

        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }
}
