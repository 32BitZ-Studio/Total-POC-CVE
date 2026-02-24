function activateNavbar(active) {
	var navbars = ["nav-training", "nav-exercises", "nav-gyms", "nav-account"];
	
	navbars.forEach(function(entry) {
		document.getElementById(entry).className = "";
	});
	document.getElementById(active).className = "active";
}