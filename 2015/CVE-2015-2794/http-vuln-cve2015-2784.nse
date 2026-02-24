-- The Head Section --
description = [[
This script attempts to detect an authentication bypass vulnerability in DotNetNuke (DNN) 07.04.00 Content 
Management System (CMS). 

The issue allows an unauthenticated attacker to create a new host (administrator) 
account to the platform. This gives them the ability to access any content stored within the application, 
make changes to the website and potentially launch further attacks against the system.

Although DNN 07.04.00 is known to be vulnerable, previous versions may be affected as well.
]]

---
-- @args uri Enter the root location of the DNN platform. If ommitted, the scripts uses "/" by default.
--
-- @usage
-- nmap --script http-vuln-cve2015-2794 <target>
-- nmap --script http-vuln-cve2015-2794 --script-args http-vuln-cve2015-2794.uri="/dnn" <target>
--
-- @output
-- PORT     STATE     SERVICE
-- 80/tcp   open      http
-- | http-vuln-cve2015-2794:
-- |   VULNERABLE:
-- |   DotNetNuke (DNN) CVE-2015-2794 Authentication Bypass Vulnerability
-- |     State: VULNERABLE
-- |     IDs: CVE:CVE-2015-2794
-- |     Risk factor: High CVSS2: 9
-- |       The issue allows an unauthenticated attacker to create a new host (administrator) 
-- |	   account to the DNN platform. This gives them the ability to access any content stored 
-- |	   within the application, make changes to the website and potentially launch further 
-- |	   attacks against the system.
-- |
-- |	   Although DNN 07.04.00 is known to be vulnerable, previous versions may be affected as well.
-- |     References:
-- |       https://www.exploit-db.com/exploits/39777/
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2794
-- |       http://www.dnnsoftware.com/platform/manage/security-center
-- |_      http://www.dnnsoftware.com/community-blog/cid/155198/workaround-for-potential-security-issue

author = "Marios Nicolaides (styx00)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)

    -- The Vuln Definition Section --
    local vuln = {
        title = "DotNetNuke (DNN) CVE-2015-2794 Authentication Bypass Vulnerability",
        state = vulns.STATE.NOT_VULN, --default,
	IDS = { CVE = 'CVE-2015-2794' },
    	risk_factor = "High",
	scores = {CVSSv2 = "9 (HIGH) (AV:N/AC:M/Au:N/C:P/I:P/A:C)",},
	description = [[
The issue allows an unauthenticated attacker to create a new host (administrator) 
account to the DNN platform. This gives them the ability to access any content stored 
within the application, make changes to the website and potentially launch further 
attacks against the system.

Although DNN 07.04.00 is known to be vulnerable, previous versions may be affected as well.
	]],

	references = {
		'https://www.exploit-db.com/exploits/39777/',
		'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2794',
		'http://www.dnnsoftware.com/platform/manage/security-center',
		'http://www.dnnsoftware.com/community-blog/cid/155198/workaround-for-potential-security-issue'
	}
    }

    local report = vulns.Report:new(SCRIPT_NAME, host, port)

    local options = {header={}}
    options['header']['User-Agent'] = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36"

    local uri = stdnse.get_script_args(SCRIPT_NAME .. ".uri") or '/'

    local response = http.get(host, port, uri .. "/Install/InstallWizard.aspx?__VIEWSTATE=", options)
    stdnse.print_debug("%s",uri)

    -- Request failed (not an HTTP server or misconfigured) --
    if not response.status then
        -- Bad response --
        stdnse.print_debug("%s: %s GET REQUEST FAILED. Are you sure that the target is an HTTP(S) server? If yes, try running the script again.", SCRIPT_NAME, host.targetname or host.ip)
        -- Exit --
        return
    end

    -- Request succeeded --
    if ( response.status == 200 ) then
	-- Extract the target's title from the HTTP response --
	local title = string.match(response.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

	if (title ~= nil) then
	    -- Remove extra whitespaces --
	    local title = title:match "^%s*(.-)%s*$"    

	    -- Check if the title contains the word 'Installation' --
	    local titleCheck = string.match(response.body, "Installation")

	    -- If the title contains the word 'Installation' the system is vulnerable, otherwise it's not --
            if (titleCheck ~= nil) then
	        stdnse.print_debug('The system appears to be VULNERABLE!' .. "\n\nTitle: " .. title)
		vuln.state = vulns.STATE.VULN
	    else
	        stdnse.print_debug('NOT VULNERABLE!' .. "\nREASON: The signature does not match.\n" .. "SIGNATURE: " .. title  .. "\n\nHTTP Response Code: " .. response.status .. stdnse.format_output(true, response.rawheader))
		vuln.state = vulns.STATE.NOT_VULN
	    end
	else
	    stdnse.print_debug('NOT VULNERABLE!' .. "\nREASON: The signature does not match.\n" .. "SIGNATURE: The page's title could not be found."  .. "\n\nHTTP Response Code: " .. response.status .. stdnse.format_output(true, response.rawheader))
	    vuln.state = vulns.STATE.NOT_VULN
	end
    else
	stdnse.print_debug('NOT VULNERABLE' .. '\nREASON: HTTP Response Code is ' .. response.status .. "." .. "\n\nHTTP Response Code: " .. response.status .. stdnse.format_output(true, response.rawheader))
	vuln.state = vulns.STATE.NOT_VULN
    end
    return report:make_output(vuln) 
end
