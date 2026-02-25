# CVE-2022-0165 - Page Builder KingComposer WordPress Plugin - ID Parameter Validation Bypass

The Page Builder KingComposer WordPress plugin, versions up to and including 2.9.6, is susceptible to a security vulnerability that allows an attacker to bypass ID parameter validation. This could lead to unauthorized redirection of users via the kc_get_thumbn AJAX action. This vulnerability has been assigned the identifier CVE-2022-0165.

# Vulnerability Details

CVE ID: CVE-2022-0165
Type: ID Parameter Validation Bypass
Affected Versions: Up to and including 2.9.6

The vulnerability arises due to inadequate validation of the id parameter when processing the kc_get_thumbn AJAX action. This action is available to both unauthenticated and authenticated users.

# Impact

Exploiting this vulnerability could allow an attacker to craft a malicious URL with a specially crafted id parameter. When a user, especially an authenticated administrator, interacts with this URL, they could be redirected to an unintended destination. This can potentially lead to phishing attacks, malware distribution, or other malicious activities.

# Proof of Concept (PoC)

To demonstrate the vulnerability, you can follow these steps:

    Craft a malicious URL with a manipulated id parameter. For example:

    http://your-wordpress-site.com/wp-admin/admin-ajax.php?action=kc_get_thumbn&id=malicious_url

    Share the crafted URL with a victim, enticing them to click on it.

    When the victim interacts with the URL, the vulnerable plugin will not properly validate the id parameter, potentially leading to unintended redirection.

# Mitigation

To mitigate the vulnerability, it is recommended to update the Page Builder KingComposer plugin to the latest version available. Plugin updates often include security fixes that address such vulnerabilities. Regularly updating plugins and themes is a best practice to ensure your WordPress site's security.
