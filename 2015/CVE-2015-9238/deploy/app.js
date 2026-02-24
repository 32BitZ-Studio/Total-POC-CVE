const express = require("express");
const path = require('path');
const fs = require("fs");
const secureCompare = require('secure-compare');
const bodyParser = require('body-parser')
const words = require("./ag")

const app = express();
const jsonParser = bodyParser.json();


const PORT = 3000; // port 3000

app.set('views', path.join(__dirname, '/static/views'));
app.set("view engine", "ejs");

app.set('case sensitive routing', true); // 경로 대소문자 구분 활성화
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ extended: true }));

function search(words, name) {
    return words.find(word => word.name === name.toUpperCase())
}

app.get('/', (req, res) => {
    res.send('hello there!!')
})

// 정적 파일 제공
app.use('/static', express.static(path.join(__dirname, 'static')));


app.post('/login', jsonParser, (req, res) => {
    console.log(req.body)
    const { username , password } = req.body
    const serverPassword = req.headers['x-server-password']

    // please, Don't try Brute forcing!!!
    setTimeout(() => {
        if (password == serverPassword) {
            return res.send('Do not hacking!!!!')
        }
        if (secureCompare(serverPassword, password) == true) { // password 변경해주세요. (password 값이 password임.)
            
        // flag is here!!!!!!
        try {
            const flag = fs.readFileSync('flag.txt', {encoding: 'utf8', flag: 'r'})
            const ip = req.header["x-forwarded-for"] || req.connection.remoteAddress
            fs.writeFileSync('./server.log', `${ip} | ${password}`, {flags: 'a'})
            return res.send(`flag is ${flag}`)
        } catch (error) {
            console.log(error)
            return res.send('Internal Server Error')
        }
        
        } else {
            return res.send('Wrong!')
        }
    }, 5000)
})

app.get("/cccc",(req, res)=>{
    res.render("index")
})


app.post("/chicken",(req, res)=>{
    const name = req.body.name.toLowerCase()
    console.log(`name: ${name}`)

    const obj = search(words,name)

    if (name == 'flag') {
        return res.status(404).send("do not hacking")
    } 
    if (obj) {
        return res.send(JSON.stringify(obj))
    }
    return res.status(404).send("Nothing")
}) // Noting 404




app.listen(PORT, () => { 
    console.log("Start")
})

