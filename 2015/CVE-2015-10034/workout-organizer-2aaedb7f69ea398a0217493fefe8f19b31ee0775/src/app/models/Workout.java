package models;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

public class Workout {

	private int id;
	private int userId;
	private Integer gymId;
	private Timestamp startedAt;
	private Timestamp finishedAt;
	private String note;
	private List<WorkoutEntry> workoutEntries;
	private String gymName;
	
	public Workout(int userId, Integer gymId, Timestamp startedAt, Timestamp finishedAt) {
		this.setUserId(userId);
		this.setGymId(gymId);
		this.setStartedAt(startedAt);
		this.setFinishedAt(finishedAt);
		workoutEntries = new ArrayList<WorkoutEntry>();
	}
	
	public void addWorkoutEntry(WorkoutEntry workoutEntry) {
		workoutEntries.add(workoutEntry);
	}
	
	public List<WorkoutEntry> getWorkoutEntries() {
		return new ArrayList<WorkoutEntry>(workoutEntries);
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public int getUserId() {
		return userId;
	}

	public void setUserId(int userId) {
		this.userId = userId;
	}

	public Integer getGymId() {
		return gymId;
	}

	public void setGymId(Integer gymId) {
		this.gymId = gymId;
	}

	public Timestamp getStartedAt() {
		return startedAt;
	}

	public void setStartedAt(Timestamp startedAt) {
		this.startedAt = startedAt;
	}

	public Timestamp getFinishedAt() {
		return finishedAt;
	}

	public void setFinishedAt(Timestamp finishedAt) {
		this.finishedAt = finishedAt;
	}

	public String getNote() {
		return note;
	}

	public void setNote(String note) {
		this.note = note;
	}

	public String getGymName() {
		return gymName;
	}

	public void setGymName(String gymName) {
		this.gymName = gymName;
	}
	
	
}
