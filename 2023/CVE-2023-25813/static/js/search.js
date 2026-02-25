var searchButton = document.getElementById("search-btn");

searchButton.addEventListener("click", function (event) {
    event.preventDefault();
    
    var username = document.getElementById("search-username").value;
    var email = document.getElementById("search-email").value;

    fetch('/search', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username: username, email: email })
    })
        .then(response => {
            if (response.ok) {
                console.log(response);
                return response.json();
            }
            throw new Error('Error');
        })
        .then(data => {
            console.log('Response:', data);
            displaySearchResults(data);
        })
        .catch(error => {
            console.log(error);
        });
});

function displaySearchResults(data) {
    const searchResultsDiv = document.querySelector('.search-results');
    searchResultsDiv.innerHTML = '';
    data.forEach(user => {
        const userElement = document.createElement('div');
        userElement.innerHTML = "<div>Username: " + user.username + "</div>" +
            "<div>Email: " + user.email + "</div>" +
            "<div>createdAt: " + user.createdAt + "</div>" +
            "<div>updatedAt: " + user.updatedAt + "</div>";
        searchResultsDiv.appendChild(userElement);
    });
}