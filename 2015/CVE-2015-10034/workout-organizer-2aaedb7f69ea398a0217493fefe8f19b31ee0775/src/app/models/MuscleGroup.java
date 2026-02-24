package models;

public class MuscleGroup {

	private String muscleName;
	
	public MuscleGroup() {}
	
	public MuscleGroup(String muscleName) {
		this.muscleName = muscleName;
	}

	public String getMuscleName() {
		return muscleName;
	}

	public void setMuscleName(String muscleName) {
		this.muscleName = muscleName;
	}
	
	@Override
	public String toString() {
		return muscleName;
	}
	
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof MuscleGroup)) {
			return false;
		}
		MuscleGroup m = (MuscleGroup)o;
		return muscleName.equals(m.muscleName);
	}
	
	@Override
	public int hashCode() {
		return muscleName.hashCode();
	}

}
