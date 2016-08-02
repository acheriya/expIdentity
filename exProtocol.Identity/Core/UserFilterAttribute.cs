using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace exProtocol.Identity.Core
{
    public class User
    {
        public string UserId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public int ProviderId { get; set; }
        public string ProviderName { get; set; }
        public int ClientId { get; set; }
        public string ClientName { get; set; }
        public string Email { get; set; }
        public bool IsAuthenticated { get; set; }
        public UserRole Role { get; set; }
    }

    public class UserFilterAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            const string Key = "user";
            User user = new User();

            if (filterContext.ActionParameters.ContainsKey(Key))
            {
                var auth = filterContext.HttpContext.GetOwinContext().Authentication;

                if (auth.User.Identity.IsAuthenticated)
                {
                    try
                    {
                        var claimsIdentity = auth.User.Identity as ClaimsIdentity;

                        user.IsAuthenticated = true;

                        user.UserId = auth.User.Identity.Name;
                        user.FirstName = claimsIdentity.Claims.FirstOrDefault(claim => claim.Type == CustomClaimTypes.FirstName).Value;
                        user.LastName = claimsIdentity.Claims.FirstOrDefault(claim => claim.Type == CustomClaimTypes.LastName).Value;
                        user.Email = claimsIdentity.Claims.FirstOrDefault(claim => claim.Type == CustomClaimTypes.Email).Value;
                        user.Role = (UserRole)Enum.Parse(typeof(UserRole), claimsIdentity.Claims.FirstOrDefault(claim => claim.Type == CustomClaimTypes.UserRole).Value);
                        user.ClientId = Convert.ToInt32(claimsIdentity.Claims.FirstOrDefault(claim => claim.Type == CustomClaimTypes.ClientId).Value);
                        user.ClientName = claimsIdentity.Claims.FirstOrDefault(claim => claim.Type == CustomClaimTypes.ClientName).Value;


                    }
                    catch (Exception)
                    {
                        //Something goes wrong, then assume that the claims are invalid. Let the user re-login
                        auth.SignOut();

                        filterContext.Result = new RedirectToRouteResult(new RouteValueDictionary { { "Controller", "account" }, { "Action", "login" }, { "Area", "" } });
                    }

                }

                filterContext.ActionParameters[Key] = user;
            }

            base.OnActionExecuting(filterContext);
        }
    }
}