package models;

public class Address {
	private String city;
	private String street;
	private Coordinates coords;
	
	public Address(String city, String street) {
		this.city = city;
		this.street = street;
	}
	
	public Address(String city, String street, Coordinates coords) {
		this(city, street);
		this.coords = coords;
	}
	
	public String getCity() {
		return city;
	}
	public void setCity(String city) {
		this.city = city;
	}
	public String getStreet() {
		return street;
	}
	public void setStreet(String street) {
		this.street = street;
	}
	public Coordinates getCoords() {
		return coords;
	}
	public void setCoords(Coordinates coords) {
		this.coords = coords;
	}
}
