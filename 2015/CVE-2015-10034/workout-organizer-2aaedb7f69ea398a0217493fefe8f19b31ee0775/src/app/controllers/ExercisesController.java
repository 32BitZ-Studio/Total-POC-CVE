package controllers;

import java.util.List;

import models.Exercise;
import models.ExerciseResult;
import models.Secured;
import play.data.DynamicForm;
import play.data.Form;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Security;
import views.html.exercises;
import database.ExerciseDao;

@Security.Authenticated(Secured.class)
public class ExercisesController extends Controller {
	
    private static final String RATING = "rating";
    private static final String MUSCLES = "muscles";
    private static final String EXERCISE_ID = "exerciseId";

	public static Result listAllExercises() {	
    	List<Exercise> exercisesList = ExerciseDao.get().getAll(); 
		return ok(exercises.render(exercisesList));
	}
	
	public static Result listFileteredExercises() {
		String muscle = request().queryString().get(MUSCLES)[0];
    	List<Exercise> exercisesList = ExerciseDao.get().filter(muscle); 
		return ok(exercises.render(exercisesList));
	}
    
    public static Result rate(int exerciseId) {
    	String userId = session(Application.USER_ID);
		DynamicForm requestData = Form.form().bindFromRequest();
		String ratingRaw = requestData.get(RATING);
		
    	try {
    		int rating = Integer.parseInt(ratingRaw);
    		if (rating < 0 || rating > 10)
    			return badRequest();

    		ExerciseDao.get().rateExercise(Integer.parseInt(userId), exerciseId, rating);
        	return ok();
    	} catch (Exception e) {
    		e.printStackTrace();
    		return badRequest();
    	}
    }

    public static Result showBestResult() {
    	DynamicForm requestData = Form.form().bindFromRequest();
    	try {
    		String userId = session(Application.USER_ID);
    		int exerciseId = Integer.parseInt(requestData.get(EXERCISE_ID));
    		ExerciseResult result = ExerciseDao.get().getBestForUser(userId, exerciseId);
    		
    		String returnData;
    		if (result == null) {
    			returnData = "You haven't done this exercise yet.";
    		}
    		else {
    			returnData = "Weight: " + result.getWeight() + ", reps: " + result.getRepsPerSet() + ", sets: " + result.getSetCount();
    		}
    		
    		return ok(returnData);
    	} catch (NumberFormatException e) {
    		return badRequest();
    	}
    	
    }
}
