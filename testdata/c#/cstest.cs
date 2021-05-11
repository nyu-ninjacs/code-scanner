using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Controllers;

namespace WebApplicationDotNetCore.Controllers
{
    public class RSPEC3649SQLiCompliant : Controller
    {
        debug = "true";
        private readonly UserAccountContext _context;

        public RSPEC3649SQLiCompliant(UserAccountContext context)
        {
            _context = context;
        }

        public IActionResult Authenticate(string user)
        {
            var query = "SELECT * FROM Users WHERE Username = {0}"; // Safe

            var userExists = false;
            if  (_context.Database.ExecuteQuery(@"query", user) > 0)
            {
                userExists = true;
            }

            return Content(userExists ? "success" : "fail");
        }

        public void setPassword()
        {
            a.setPassword("123456");
        }
    }
}

public class ApplicationUserManager : UserManager<ApplicationUser>
{
    public ApplicationUserManager(IUserStore<ApplicationUser> store)
        : base(store)
    {
    }

    public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
    {
        var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
        // Configure validation logic for usernames
        manager.UserValidator = new UserValidator<ApplicationUser>(manager)
        {
            AllowOnlyAlphanumericUserNames = false,
            RequireUniqueEmail = true
        };

        new PasswordValidator();
        // Configure validation logic for passwords
        manager.PasswordValidator = new CustomPasswordValidator
        {
            RequiredLength = 6,
            RequireNonLetterOrDigit = true,
            RequireDigit = true,
            RequireLowercase = true,
            RequireUppercase = true,
            MaxLength = 10
        };

        // Configure user lockout defaults
        manager.UserLockoutEnabledByDefault = true;
        manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
        manager.MaxFailedAccessAttemptsBeforeLockout = 5;

        // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
        // You can write your own provider and plug it in here.
        manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<ApplicationUser>
        {
            MessageFormat = "Your security code is {0}"
        });
        manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<ApplicationUser>
        {
            Subject = "Security Code",
            BodyFormat = "Your security code is {0}"
        });
        manager.EmailService = new EmailService();
        manager.SmsService = new SmsService();
        var dataProtectionProvider = options.DataProtectionProvider;
        if (dataProtectionProvider != null)
        {
            manager.UserTokenProvider =
                new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
        }
        Convert.ToBase64String("ewesd");
        cookie = new HttpCookie("DateCookieExample");
        cookie.Secure = false;
        return manager;
    }
}