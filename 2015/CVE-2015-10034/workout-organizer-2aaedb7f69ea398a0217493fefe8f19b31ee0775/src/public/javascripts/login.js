document.addEventListener("DOMContentLoaded", function(event) { 
	document.getElementById("signup").addEventListener("click", function() {
		document.getElementById("signup").className += " active";
		document.getElementById("login").className = "login-tab";
		document.getElementById("forgot-pass").className = "login-tab";
		
		document.getElementById("signup-container").className = "";
		document.getElementById("login-container").className = "invisible";
	});
	
	document.getElementById("login").addEventListener("click", function() {
		document.getElementById("signup").className = "login-tab";
		document.getElementById("login").className += " active";
		document.getElementById("forgot-pass").className = "login-tab";
		
		document.getElementById("signup-container").className = "invisible";
		document.getElementById("login-container").className = "";
	});
});