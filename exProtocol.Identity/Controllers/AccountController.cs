using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using exProtocol.Identity.Core;
using Microsoft.AspNet.Identity.Owin;
using exProtocol.Identity.Models;

namespace exProtocol.Identity.Controllers
{

    [Authorize]
    public class AccountController : Controller
    {

        private IdentityManager identityManager;

        public AccountController()
            : this(new IdentityManager())
        {
        }

        public AccountController(IdentityManager identityManager)
        {
            this.identityManager = identityManager;
        }

        [AllowAnonymous]
        public ActionResult Login()
        {
            if(Request.IsAuthenticated)
            { 
                return RedirectToAction("Index", "Home", new { });
            }

            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken()]
        public ActionResult Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = identityManager.SignIn(model.Email, model.Password, model.RememberMe);

                switch (result)
                {
                    case SignInStatus.Success:
                        return RedirectToAction("Index", "Home", new { });
                    case SignInStatus.Failure:
                    default:
                        ModelState.AddModelError("", "Invalid login attempt.");
                        return View(model);
                }
            }
            return View(model);
        }

        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            identityManager.SignOut();
            return RedirectToAction("Login", "Account");
        }

        [AllowAnonymous]
        [UserFilter]
        public PartialViewResult LoginSummary(User user)
        {
            return PartialView("_LoginSummary", new LoginSummaryViewModel() { IsAuthenticated = user.IsAuthenticated, FirstName = user.FirstName, LastName = user.LastName, ClientName = user.ClientName });
        }
    }
}