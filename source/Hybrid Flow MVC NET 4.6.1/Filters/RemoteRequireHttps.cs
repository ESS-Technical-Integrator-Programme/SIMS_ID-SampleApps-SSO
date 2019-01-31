using System;
using System.Web.Mvc;


public class RemoteRequireHttps : RequireHttpsAttribute
{
    public override void OnAuthorization(AuthorizationContext filterContext)
    {
        if (filterContext == null)
        {
            throw new ArgumentNullException("filterContext");
        }
        if (filterContext.HttpContext != null && filterContext.HttpContext.Request.IsLocal)
        {
            return;
        }
        base.OnAuthorization(filterContext);
    }
}
