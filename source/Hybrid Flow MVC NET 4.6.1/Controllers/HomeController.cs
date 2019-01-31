using System.Web.Mvc;

namespace Hybrid_Flow.Controllers
{
    [RemoteRequireHttps]
    [Authorize]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
    }
}