var loginForm = document.getElementById("login-form");

loginForm.addEventListener("submit", function(event) {
    event.preventDefault();

    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;

    const data = {
        username: username,
        password: password
    }

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
        .then(response => {
            if (response.ok) {
                return response.text();
            }
            throw new Error('Error');
        })
        .then(data => {
            if (data == 'success') {
                alert(data);
                window.location.href = '/';
            } else {
                alert(data);
            }
            console.log(data);
        })
        .catch(error => {
            console.log(error);
    })
});