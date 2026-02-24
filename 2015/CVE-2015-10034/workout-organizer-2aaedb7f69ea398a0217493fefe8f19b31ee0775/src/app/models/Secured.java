package models;

import play.mvc.Http.Context;
import play.mvc.Result;
import play.mvc.Security;
import controllers.Application;

public class Secured extends Security.Authenticator {

	@Override
	public String getUsername(Context ctx) {
		return ctx.session().get(Application.USER_ID);
	}
	
	@Override
	public Result onUnauthorized(Context ctx) {
		return redirect(Application.LOGIN);
	}
	
}
