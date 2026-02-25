const express = require('express');
const app = express();
const fs = require('fs');
const moment = require('moment');
const multer = require('multer');
const os = require('os');
const path = require('path');

const ip = '0.0.0.0';
const port = 8000;
const sendFile = (res, file) => {
    res.sendFile(path.join(__dirname, file));
};

// Storage for multer uploads
const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    },
});
const upload = multer({ storage });

// Statics
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Routes
app.route('/serveripport')
    .get(function (req, res) {
        const serverIP = req.connection.localAddress;
        if (serverIP.substr(0, 7) == "::ffff:") {
            serverIP = serverIP.substr(7);
        }
        const serverPort = req.connection.localPort;
        res.json({ serverIP: serverIP, serverPort: serverPort });
    });

app.route('/home')
    .get((req, res) => {
        res.sendFile(path.join(__dirname, 'assets/html/home.html'));
    });

app.route('/node_modules/moment/moment.js')
    .get((req, res) => {
        sendFile(res, 'node_modules/moment/moment.js');
    });

app.route('/moment')
    .get((req, res) => {
        if (req.query.localeId) {
            const momentResponse = getMomentResponse(req.query.localeId, req.socket.remoteAddress);
            res.json(momentResponse);
        } else {
            sendFile(res, 'assets/html/moment.html');
        }
    })
    .post((req, res) => {
        res.send(getMomentResponse(req.body.localeId, req.socket.remoteAddress));
    });

app.route('/upload')
    .get((req, res) => {
        sendFile(res, 'assets/html/upload.html');
    })
    .post(upload.single('fileInput'), (req, res) => {
        const filename = req.file.filename;
        const responseHtml = `
          <script>
              window.location.href = "/upload?filename=${filename}";
          </script>
        `;
        res.send(responseHtml);
    });

app.route('/uploads')
    .get((req, res, next) => {
        fs.readdir(path.join(__dirname, 'uploads'), (err, files) => {
            if (err) {
                console.error(err);
                next(err);
            } else {
                const fileHTML = files
                    .map(file => `<li><a href="/uploads/${file}">${file}</a></li>`)
                    .join('');
                const html = `
                    <!DOCTYPE html>
                    <html lang="en">
                    <html>
                        <head>
                            <link rel="icon" type="image/x-icon" href="/assets/img/favicon.ico">
                            <link rel="stylesheet" type="text/css" href="/assets/css/bootstrap.css">
                            <link rel="stylesheet" type="text/css" href="/assets/css/dark-theme.css">
                        </head>
                        <body>
                        <!-- Navbar -->
                        <nav class="navbar navbar-expand-lg navbar-light bg-light">
                            <div class="container-fluid">
                                <h3>Moment.js Vuln Lab</h3>
                                <h6><span class="text-muted">Ain't nobody got time for that!</span></h6>
                                <a class="nav-link" href="/home">Home</a> |
                                <a class="nav-link" href="/upload">Upload</a> |
                                <a class="nav-link" href="/uploads/">Uploads</a> |
                                <a class="nav-link" href="/moment">Moment</a>
                            </div>
                        </nav>
                        <!-- Main Content -->
                        <div class="container mt-4">
                            <div class="card mt-3">
                                <div class="card-body">
                                    <h4 class="card-title">Uploaded files:</h4>
                                    <ul>${fileHTML}</ul>
                                </div>
                            </div>
                        </div>
                        </body>
                  </html>
                `;
                res.send(html);
            }
        });
    });

app.all('*', (req, res) => {
    res.redirect(302, '/home');
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

// Helpers
function getMomentResponse(localeId, clientIp) {
    const response = {
        providedLocale: localeId,
        'current moment.Locale': setLocale(localeId),
    };
    const allServerIPs = getAllServerIPs();
    if (allServerIPs.includes(clientIp)) {
        response.Warning =
            'You are accessing this server from one of the server IP addresses. Traversal testing may be affected.';
    }
    return response;
}

function getAllServerIPs() {
    const interfaces = os.networkInterfaces();
    return Object.values(interfaces)
        .flatMap(iface =>
            iface.filter(f => f.family === 'IPv4').map(f => f.address)
        );
}

function getServerIPs() {
    const interfaces = os.networkInterfaces();
    return Object.values(interfaces)
        .flatMap(iface =>
            iface.filter(f => f.family === 'IPv4' && !f.internal).map(f => f.address)
        );
}

// Taken from Moment v2.29.2's patch
function isLocaleNameSane(name) {
    // Prevent names that look like filesystem paths, i.e contain '/' or '\'
    return name.match('^[^/\\\\]*$') != null;
}

function setLocale(providedLocale) {
    moment.locale('en');
    const momentsLocale = moment.locale(providedLocale);
    console.log(
        `moment.locale was reset to: en\nprovidedLocale was: ${providedLocale}\nmomentsLocale is: ${momentsLocale}\n`
    );
    return momentsLocale;
}

// Start server
app.listen(port, ip, () => {
    console.log('Server is listening on all interfaces. For traversal testing, access it from a remote client:');
    const serverIPs = getServerIPs();
    serverIPs.forEach(ip => {
        console.log(`http://${ip}:${port}`);
    });
});
