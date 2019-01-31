using System.Web;
using System.Web.Mvc;

namespace Hybrid_Flow.Controllers
{
    public class AccountController : Controller
    {
        [Authorize]
        public ActionResult LogOut()
        {
            Request.GetOwinContext().Authentication.SignOut();
            return RedirectToAction("Index", "Home");
        }
    }
}