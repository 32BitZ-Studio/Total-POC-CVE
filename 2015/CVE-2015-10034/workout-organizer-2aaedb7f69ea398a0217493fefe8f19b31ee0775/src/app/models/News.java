package models;

import java.sql.Timestamp;

public class News {
	
	private int friendId;
	private String firstName;
	private String lastName;
	private int workoutId;
	private int gymId;
	private String gymName;
	private Timestamp startedAt;
	private Timestamp finishedAt;
	private String note;
	private String[] musclesNames;
	private int likesCount;
	private boolean liked;
	
	public News() {
		
	}

	public int getFriendId() {
		return friendId;
	}

	public void setFriendId(int friendId) {
		this.friendId = friendId;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public int getGymId() {
		return gymId;
	}

	public void setGymId(int gymId) {
		this.gymId = gymId;
	}

	public String getGymName() {
		return gymName;
	}

	public void setGymName(String gymName) {
		this.gymName = gymName;
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

	public String[] getMusclesNames() {
		return musclesNames;
	}

	public void setMusclesNames(String[] musclesNames) {
		this.musclesNames = musclesNames;
	}

	public int getLikesCount() {
		return likesCount;
	}

	public void setLikesCount(int likesCount) {
		this.likesCount = likesCount;
	}
	
	public String listMuscles() {
		StringBuilder sb = new StringBuilder();
		
		for (int i = 0; i < musclesNames.length - 2; ++i) {
			sb.append(musclesNames[i]);
			sb.append(", ");
		}
		if (musclesNames.length >= 2) {
			sb.append(musclesNames[musclesNames.length - 2]);
			sb.append(" and ");
		}
		if (musclesNames.length >= 1) {
			sb.append(musclesNames[musclesNames.length - 1]);
		}
		
		return sb.toString();
	}

	public int getWorkoutId() {
		return workoutId;
	}

	public void setWorkoutId(int workoutId) {
		this.workoutId = workoutId;
	}

	public boolean isLiked() {
		return liked;
	}

	public void setLiked(boolean liked) {
		this.liked = liked;
	}

}
