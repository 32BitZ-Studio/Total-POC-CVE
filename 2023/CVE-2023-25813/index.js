const models = require('./models');
const User = models.User;
const express = require('express');
const path = require('path');
const app = express();
const { Op, or, literal, Sequelize } = require('sequelize');
const PORT = process.env.PORT || 3000;
const session = require('express-session');

models.sequelize.sync().then(() => {
    console.log(" DB 연결 성공");

}).catch(err => {
    console.log("연결 실패");
    console.log(err);
})

app.use(session({
    secret: 'secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 1000 * 60 * 60 
    }
}));

app.use('/static', express.static(path.join(__dirname, 'static')));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

app.get('/join', (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'join.html'));
});

app.get('/test', (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'test.html'));
});

app.post('/join', async (req, res) => {
    const { firstname, lastname, password, email } = req.body;
    const username = firstname + lastname;

    try {
        const newUser = await User.create({
            firstname,
            lastname,
            username,
            password,
            email
        });
        res.send('<h1>Register Successful</h1>Go to <a href="/login">Login</a>');

    } catch(error) {
        console.error('가입 실패:',error)
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'login.html'));
});

app.post('/login', (req, res) => {
    const username = req.body.username
    const password = req.body.password
    User.findOne({
        where: or(
            literal('LOWER("username") = LOWER(:username)'),
            { password: password },
        ),
    replacements: { username: username },
    }).then(users => {
        if (users.length > 0) {
            req.session.user = users[0];
            res.send('success');
            console.log(users);
        } else {
            res.send('No User Found');
    }
    }).catch(error => {
    console.error("Query failed:", error);
    });
})

app.get('/search', (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'search.html'));
});

app.post('/search', (req, res) => {

    const username = req.body.username
    const email = req.body.email
    User.findOne({
        where: or(
            literal('TRIM("username") = TRIM(:username)'),
            { email: email },
        ),
    replacements: { username: username },
    }).then(users => {
        res.json(users);
        console.log(users);
    }).catch(error => {
        console.error(error);
    });
})

app.get('/users', (req, res) => {
    User.findAll()
        .then(users => {
            res.json(users);
        })
        .catch(error => {
            console.error(error);
        });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});