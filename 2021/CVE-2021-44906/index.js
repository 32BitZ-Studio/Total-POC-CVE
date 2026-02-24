const minimist = require("minimist");

const args = minimist(process.argv);
//arr=[]
//console.log(arr.toString)

//the done property is polluted
function performSecurityCheck() {
  if (!performSecurityCheck.done) {
    console.log("performSecurityCheck.done is false");
    performSecurityCheck.done = true;
  }
  else {
    console.log("performSecurityCheck.done is true");
  }
}

//toString function is polluted to a value
console.log(performSecurityCheck.toString)

for (let i = 0; i < 5; i++) {
  console.log(`Operation ${i}`);
  try {
    performSecurityCheck();
    //console.log(performSecurityCheck.done)
  } catch (error) {
    console.error(error);
  }
}
