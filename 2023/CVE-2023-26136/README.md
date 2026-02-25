# Tough-Cookie v2.5.0 Patched - Prototype Pollution Fix

## Overview

This repository contains a patched version of the `tough-cookie` package, version 2.5.0, to address the critical **Prototype Pollution** vulnerability (CVE-2023-26136). The vulnerability allows attackers to manipulate the prototype chain by injecting properties into JavaScript objects. This can lead to unexpected behavior, security risks such as remote code execution, and compatibility issues in applications relying on this package.

### Vulnerability Description

Versions of the `tough-cookie` package prior to v4.1.3 are vulnerable to **Prototype Pollution** when using the `CookieJar` with `rejectPublicSuffixes=false` mode. The vulnerability arises from improper handling of cookies, specifically when the `cookie.domain` is set to `__proto__`. This allows attackers to modify the core `Object.prototype` object, potentially causing widespread issues throughout the application.

For more details on the CVE-2023-26136, check out:
- [NVD - CVE-2023-26136](https://nvd.nist.gov/vuln/detail/CVE-2023-26136)
- [Snyk - CVE-2023-26136 in Tough-Cookie](https://security.snyk.io/vuln/SNYK-JS-TOUGHCOOKIE-5672873)
- [GitHub - Issue #282](https://github.com/salesforce/tough-cookie/issues/282)

## Potential Risks of Prototype Pollution
Prototype pollution can introduce several critical risks, including:

- **Security Vulnerabilities**: By modifying the base `Object.prototype`, attackers can manipulate the behavior of objects, potentially escalating privileges, accessing sensitive data, or bypassing security mechanisms in the application.

- **Denial of Service (DoS)**: Polluting the prototype chain can cause unexpected behavior in the system, leading to crashes, infinite loops, or resource exhaustion, making the application unavailable to legitimate users.

- **Compatibility Issues**: Changing the `Object.prototype` can cause errors and unexpected behavior when interacting with other libraries or frameworks. Dependencies that rely on prototype chains may break, leading to integration problems or faulty application behavior during updates.

- **Unexpected Application Behavior**: Prototype pollution can lead to erratic program behavior, including data corruption, security breaches, and potentially exposing the application to further exploits.

## Key Fixes

The patch involves modifying the `MemoryCookieStore` class, specifically the `putCookie` method, to prevent prototype pollution by creating prototype-free objects. The key changes include:

1. **Using `Object.create(null)`** instead of `{}` to create objects with no prototype.
2. **Fixing the vulnerability** where cookies could be set with `cookie.domain = __proto__`.
3. **Adding tests** to verify that the vulnerability is properly addressed.

## Installing the Patched Version
To install the patched version of tough-cookie, use the following command:
```bash
npm install ./tough-cookie-2.5.0-PATCHED.tgz
```

## Testing the Fix

This repository includes a unit test designed to verify that the prototype pollution vulnerability has been successfully addressed.

The test, named `prototype_pollution_test`, specifically checks that setting cookies with a domain of `__proto__` no longer affects the JavaScript prototype chain. This ensures that prototype pollution is prevented, maintaining the integrity of the application.

To run the tests and confirm the fix, execute the following command:

```bash
npm test
```

## Exploit Demonstration

To demonstrate the exploit in both the original and patched versions, follow the steps below:

### Original Vulnerable Version
Install the vulnerable version of `tough-cookie`:
   ```bash
   npm install tough-cookie@2.5.0 && node index.js
   ```

**Expected Output**:
```
Polluted object: {
  Slonser: Cookie="Slonser=polluted; Domain=__proto__; Path=/notauth; hostOnly=false; aAge=5ms; cAge=5ms",
  Auth: Cookie="Auth=Lol; Domain=google.com; Path=/notauth; hostOnly=false; aAge=5ms; cAge=5ms"
} EXPLOITED SUCCESSFULLY
```
This indicates that the prototype of an object has been polluted, confirming the vulnerability is present in the original version.

### Patched Version
   ```bash
    npm install ./tough-cookie-2.5.0-PATCHED.tgz && node index.js
   ```

**Expected Output**:
```
EXPLOIT FAILED
```
This shows that the exploit has been successfully blocked, confirming that the prototype pollution vulnerability has been fixed.

## Approach and Steps Taken

The process of addressing the **Prototype Pollution** vulnerability in `tough-cookie` v2.5.0 involved several methodical steps to ensure that the fix was thorough and effective. Below is an overview of the approach I followed:

### 1. Understand the Vulnerability
I started by researching **Prototype Pollution** (CVE-2023-26136) to understand its impact. The vulnerability allows attackers to inject properties into the prototype chain via the `cookie.domain` property, potentially causing security risks like remote code execution.

### 2. Research Existing Fixes
I explored GitHub issues and discussions around the vulnerability, including the fix in `tough-cookie` v4.1.3, which uses `Object.create(null)` to prevent prototype pollution. This helped me identify the changes needed to fix v2.5.0.

### 3. Analyze Vulnerable and Patched Versions
I compared v2.5.0 with v4.1.3 to understand the differences and pinpoint the necessary changes. The key modification involved using prototype-free objects to prevent exploitation.

### 4. Implement the Solution
I updated the `MemoryCookieStore` class to use `Object.create(null)` instead of `{}`, ensuring no prototype pollution.

### 5. Testing the Solution
I wrote unit tests to verify the fix and created an exploit demonstration script (`index.js`) to show how the vulnerability is prevented in the patched version.

### 6. Documenting the Fix
Finally, I documented the fix, including installation and testing instructions, and packaged the patched version (`tough-cookie-2.5.0-PATCHED.tgz`) for easy distribution.


## Summary of Changes

Files Added/Edited from v2.5.0

- **`index.js`**: Main script to demonstrate the vulnerability and fix.
- **`lib/memstore.js`**: The modified `MemoryCookieStore` class to prevent prototype pollution.
- **`test/ietf_data/parser.json`**: Updated to edit outdated dates in the test data.
- **`test/prototype_pollution_test.js`**: Unit tests to verify that prototype pollution is fixed.
- **`tough-cookie-2.5.0-PATCHED.tgz`**: The patched version of the `tough-cookie` package.





