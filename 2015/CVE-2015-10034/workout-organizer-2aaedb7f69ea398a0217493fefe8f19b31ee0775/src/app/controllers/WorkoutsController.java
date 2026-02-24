package controllers;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;

import models.Exercise;
import models.Gym;
import models.Secured;
import models.Workout;
import models.WorkoutEntry;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Security;
import views.html.workouts_index;
import views.html.workouts_new;
import database.ExerciseDao;
import database.GymsDao;
import database.WorkoutDao;

@Security.Authenticated(Secured.class)
public class WorkoutsController extends Controller {
	
	public static Result buildNew() {
    	List<Exercise> exercisesList = ExerciseDao.get().getAll(); 
    	List<Gym> gymsList = GymsDao.get().getAll();
    	
		return ok(workouts_new.render(exercisesList, gymsList));
	}
	
	public static Result index() {
		try {
			int userId = Integer.parseInt(session().get(Application.USER_ID));
			List<Workout> workouts = WorkoutDao.get().getUserWorkouts(userId);
			return ok(workouts_index.render(workouts));
		} catch (Exception e) {
			e.printStackTrace();
			return internalServerError();
		}
	}
	
	public static Result like(int workoutId) {
		try {
			int userId = Integer.parseInt(session().get(Application.USER_ID));
			int likesCount = WorkoutDao.get().like(workoutId, userId);
			return ok("" + likesCount);
		} catch (Exception e) {
			e.printStackTrace();
			return internalServerError();
		}
	}
	
	public static Result create() {
		Map<String, String[]> params = request().body().asFormUrlEncoded();
		
		try {
			String userId = session().get(Application.USER_ID);
			String gymId = params.get("gymId")[0];
			String startedAt =  params.get("startedAt")[0];
			String finishedAt = params.get("finishedAt")[0];
			String note = params.get("note")[0];
			String[] exerciseId = params.get("entries[][exerciseId]");
			String[] setsCount = params.get("entries[][setsCount]");
			String[] repsPerSet = params.get("entries[][repsPerSet]");
			String[] weight = params.get("entries[][weight]"); 

			startedAt = startedAt.replace("T", " ") + ":00";
			finishedAt = finishedAt.replace("T", " ") + ":00";
			Workout workout = new Workout(Integer.parseInt(userId), Integer.parseInt(gymId), Timestamp.valueOf(startedAt), Timestamp.valueOf(finishedAt));
			workout.setNote(note);
			
			for (int i = 0; i < exerciseId.length; ++i) {
				WorkoutEntry entry = new WorkoutEntry();
				
				entry.setExerciseId(Integer.parseInt(exerciseId[i]));
				entry.setSetsCount(Integer.parseInt(setsCount[i]));
				if (!repsPerSet[i].isEmpty())
					entry.setRepsPerSet(Integer.parseInt(repsPerSet[i]));
				if (!weight[i].isEmpty())
					entry.setWeight(Double.parseDouble(weight[i]));
				workout.addWorkoutEntry(entry);
			}
			
			WorkoutDao.get().create(workout);
			return ok();
		} catch (Exception e) {
			e.printStackTrace();
			return badRequest();
		}
	}
}
