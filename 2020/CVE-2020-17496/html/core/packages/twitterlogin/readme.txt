1) Create a twitter account

2) Create an app with your twitter account
https://apps.twitter.com/
https://apps.twitter.com/app/new

3) Check App Settings
Go to the application settings (e.g. https://apps.twitter.com/app/12345/settings where 12345
references the app created in step 2). You can access the settings by going to the list of
your apps (https://apps.twitter.com), clicking on the app link, then clicking on the
"Settings" tab.
Fill in the "Name", "Description", "Website", and "Callback URL" fields.
For the "Callback URL" field, it should be {forumurl}/twitterlogin/auth_callback (e.g.
https://yourdomain.com/yourforum/twitterlogin/auth_callback )
Make sure to check "Allow this application to be used to Sign in with Twitter".
Both "Callback URL" and "Allow this application to be used to Sign in with Twitter" settings
are REQUIRED for connect & log-in features.
Remember to click "Update Settings" before moving on.

4) App Key & Secret
After saving the settings, go to the "Keys and Access Tokens" tab.
Save the "Consumer Key (API Key)" and "Consumer Secret (API Secret)" values somewhere secure.
DO NOT SHARE THESE VALUES.
The "Consumer Key (API Key)" and "Consumer Secret (API Secret)" will be saved in the
vBulletin settings "Twitter App Consumer Key (API Key)" and "Twitter App Consumer Secret
(API Secret)", respectively. These options are under the "Third Party Login Options" setting
group.

5) (Optional) Request Emails
To allow auto-populating the email field when a guest registers with twitter, go to the
application permissions (e.g. https://apps.twitter.com/app/12345/permissions) and check the
"Request email addresses from users" checkbox under "Additional Permissions".
Note that this will require you fill in the "Privacy Policy URL" & "Terms of Service URL"
fields in the application settings.
Note that regular connect & log-in will work without this additional permission. Connecting
to twitter at registration will also work without this additional permission, but the email
will not be auto-populated on the registration form. Also note that the email may not be
populated even with this setting if the twitter account has not verified their email.

6) vBulletin Settings
Install or upgrade to vBulletin 5.4.1. If you upgraded and product & hook system is disabled,
you must enable the system.
In Admin Control Panel (Admin CP) go to "Products & Hooks" > "Manage Products". If the
product & hook system is disabled, there will be a link at the top of this page to enable it.
You should see "Third Party Login - Twitter" as one of the installed products on this page.
Click on the "Enable Sign-in with Twitter" under "Related Options".
Set "Enable Sign-in with Twitter" to "Yes", and enter the "Consumer Key (API Key)" and
"Consumer Secret (API Secret)" values from step 4 to "Twitter App Consumer Key (API Key)" and
"Twitter App Consumer Secret (API Secret)", respectively.
(Optional) Set "Enable Registration with Twitter" to allow new users to connect their twitter
accounts during registration.
Save the settings.


7) Connect/disconnect Twitter account
Your forum's users should now be able to connect (or disconnect) their twitter accounts.
Existing users can do so via the "Third-party Login Providers" section of their user settings
page after logging into the forum ({forumurl}/settings/account) and clicking on the "Connect
to Twitter" button (or "Disconnect from Twitter" button if they are already connected) in
that section.
If "Enable Sign-in with Twitter" was enabled, new users can connect their twitter accounts
during registration via the "Connect to Twitter" button at the top of the registration form.