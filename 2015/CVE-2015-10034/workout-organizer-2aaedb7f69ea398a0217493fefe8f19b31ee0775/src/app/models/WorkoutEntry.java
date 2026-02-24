package models;

public class WorkoutEntry {
	
	private int workoutId;
	private int exerciseId;
	private int setsCount;
	private Integer repsPerSet;
	private Double weight;
	
	public WorkoutEntry() {
		
	}
	
	public int getWorkoutId() {
		return workoutId;
	}
	public void setWorkoutId(int workoutId) {
		this.workoutId = workoutId;
	}
	public int getExerciseId() {
		return exerciseId;
	}
	public void setExerciseId(int exerciseId) {
		this.exerciseId = exerciseId;
	}
	public int getSetsCount() {
		return setsCount;
	}
	public void setSetsCount(int setCount) {
		this.setsCount = setCount;
	}
	public Integer getRepsPerSet() {
		return repsPerSet;
	}
	public void setRepsPerSet(Integer repsPerSet) {
		this.repsPerSet = repsPerSet;
	}
	public Double getWeight() {
		return weight;
	}
	public void setWeight(Double weight) {
		this.weight = weight;
	}

}
