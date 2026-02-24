package controllers;

import java.util.List;

import models.Gym;
import models.Secured;
import play.data.DynamicForm;
import play.data.Form;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Security;
import views.html.gym_info;
import views.html.gyms;
import database.GymsDao;

@Security.Authenticated(Secured.class)
public class GymsController extends Controller {
	
    private static final String RATING = "rating";

    
    public static Result listAllGyms() {
    	List<Gym> gymsList = GymsDao.get().getAll();
    	return ok(gyms.render(gymsList));
    }
    
    public static Result rate(int gymId) {
    	String userId = session(Application.USER_ID);
		DynamicForm requestData = Form.form().bindFromRequest();
		String ratingRaw = requestData.get(RATING);
		
    	try {
    		int rating = Integer.parseInt(ratingRaw);
    		if (rating < 0 || rating > 10)
    			return badRequest();

    		GymsDao.get().rateGym(Integer.parseInt(userId), gymId, rating);
        	return ok();
    	} catch (Exception e) {
    		e.printStackTrace();
    		return badRequest();
    	}
    }

    public static Result showGym(int id) {
    	Gym g = GymsDao.get().getById(id);
    	if (g != null) {
    		return ok(gym_info.render(g));    		
    	}
    	else {
    		return badRequest();
    	}
    }
}
