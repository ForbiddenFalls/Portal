using Microsoft.Owin.Testing;

namespace Portal.Web.Controllers
{
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Threading.Tasks;
    using System.Web.Http;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Cookies;
    using Portal.Web.Models;

    [Authorize]
    [RoutePrefix("api")]
    public class AccountController : ApiController
    {
        private ApplicationUserManager _userManager;
        private const int InitialMoney = 1000;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // POST api/user/login
        [HttpPost]
        [AllowAnonymous]
        [Route("Login")]
        public async Task<IHttpActionResult> LoginUser(LoginBindingModel model)
        {
            if (model == null)
            {
                return this.BadRequest("Invalid user data");
            }

            // Invoke the "token" OWIN service to perform the login (POST /api/token)
            var testServer = TestServer.Create<Startup>();
            var requestParams = new List<KeyValuePair<string, string>>
    {
        new KeyValuePair<string, string>("grant_type", "password"),
        new KeyValuePair<string, string>("username", model.Username),
        new KeyValuePair<string, string>("password", model.Password)
    };
            var requestParamsFormUrlEncoded = new FormUrlEncodedContent(requestParams);
            var tokenServiceResponse = await testServer.HttpClient.PostAsync(
                "/Token", requestParamsFormUrlEncoded);

            return this.ResponseMessage(tokenServiceResponse);
        }

        // POST api/user/register
        [HttpPost]
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> RegisterUser(RegisterBindingModel model)
        {
            if (model == null)
            {
                return this.BadRequest("Invalid user data");
            }

            if (!ModelState.IsValid)
            {
                return this.BadRequest(this.ModelState);
            }

            var user = new User
            {
                UserName = model.UserName,
                Email = model.Email,
                Money = InitialMoney
            };

            var identityResult = await this.UserManager.CreateAsync(user, model.Password);

            if (!identityResult.Succeeded)
            {
                return this.GetErrorResult(identityResult);
            }

            // Auto login after registrаtion (successful user registration should return access_token)
            var loginResult = await this.LoginUser(new LoginBindingModel()
            {
                Username = model.UserName,
                Password = model.Password
            });
            return loginResult;
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        #endregion
    }
}
