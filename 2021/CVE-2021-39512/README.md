# BigTreeCMS-v4.4.14-Unauthenticated-CSRF-AccountTakeOver
Unauthenticated CSRF Account TakeOver in BigTreeCMS v4.4.14

All searchable modules in the admin panel of BigTreeCMS v4.4.14 are vulnerable to reflected DOM-XSS via the URI. Search queries are reflected on the page without proper sanitization, leading to arbitrary javascript execution. CSRF Tokens are also stored within easily callable variables on all pages, making it possible for an unauthenticated attacker to forge a request as Administrator or Developer via clickjacking.

## DOM-XSS
URI: /site/index.php/admin/{module_name}/?search={search_query}
* Search queries are reflected on the page and stored in the variable BigTree.localSearchQuery
 ![echoed search](https://i.imgur.com/U2H3I4c.png)
 * This can be exploited with either a closing HTML **</script>** tag, or by ending the declaration of the BigTree.localSearchQuery variable with **";** and any arbitrary code.
 ![domxss](https://user-images.githubusercontent.com/78179391/130305895-ac8e70d2-8ee0-4355-a55f-1b70cfcbef16.gif)

 
 With this an attacker could create a clickjacking attack via an email, or a malicious link on a webpage they're hosting, that could forge requests as the targeted user.
 ![csrf](https://user-images.githubusercontent.com/78179391/130305883-46947a03-6aed-4dd2-bc99-e4a5a8ae50cf.gif)

 
 The payload provided forges a request as user id 1, and will change that user's email and password.
 
 Discovered by @giuseppesec August 20th, 2021
