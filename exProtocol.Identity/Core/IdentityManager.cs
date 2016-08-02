using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace exProtocol.Identity.Core
{
    public enum UserRole
    {
        None = 0,
        SiteAdmin = 1,
        UserAdmin = 3,
        User = 4
    }

    public static class CustomClaimTypes
    {
        public static string FirstName = "FirstName";
        public static string LastName = "LastName";
        public static string ClientId = "ClientId";
        public static string ClientName = "ClientName";
        public static string Email = "Email";
        public static string UserRole = "UserRole";
    }

    public class IdentityManager
    {
        public SignInStatus SignIn(string email, string password, bool rememberMe)
        {
            bool IsValid = (email.ToLower() == "demo@exprotocol.com" && password == "demo123456");   //Validate user credential against your db here

            if (IsValid)
            {

                var userInfo = new { userId = "user12454", firstName = "Anas", lastName = "KVC", clientId = 14589, clientName = "Client XYZ", roleId = 3 };   //Find the user info from database

                var ident = new ClaimsIdentity(DefaultAuthenticationTypes.ApplicationCookie);

                ident.AddClaim(new Claim(ClaimTypes.NameIdentifier, userInfo.userId));
                ident.AddClaim(new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "ASP.NET Identity", "http://www.w3.org/2001/XMLSchema#string"));
                ident.AddClaim(new Claim(ClaimTypes.Name, userInfo.userId));
                ident.AddClaim(new Claim(CustomClaimTypes.FirstName, userInfo.firstName));
                ident.AddClaim(new Claim(CustomClaimTypes.LastName, userInfo.lastName));
                ident.AddClaim(new Claim(CustomClaimTypes.ClientId, Convert.ToString(userInfo.clientId)));
                ident.AddClaim(new Claim(CustomClaimTypes.ClientName, userInfo.clientName));
                ident.AddClaim(new Claim(CustomClaimTypes.Email, email));
                ident.AddClaim(new Claim(CustomClaimTypes.UserRole, Convert.ToString(userInfo.roleId)));

                //Set the role
                if (userInfo.roleId == (short)UserRole.SiteAdmin)
                    ident.AddClaim(new Claim(ClaimTypes.Role, UserRole.SiteAdmin.ToString()));
                else if (userInfo.roleId == (short)UserRole.UserAdmin)
                    ident.AddClaim(new Claim(ClaimTypes.Role, UserRole.UserAdmin.ToString()));
                else if (userInfo.roleId == (short)UserRole.User)
                    ident.AddClaim(new Claim(ClaimTypes.Role, UserRole.User.ToString()));

                HttpContext.Current.GetOwinContext().Authentication.SignIn(new AuthenticationProperties { IsPersistent = rememberMe }, ident);   //Sign In

                return SignInStatus.Success;

            }

            return SignInStatus.Failure;
        }

        public void SignOut()
        {
            //Sign-out from the application
            HttpContext.Current.GetOwinContext().Authentication.SignOut();
        }
    }
}