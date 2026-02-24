===Creating a Google API Console Project:===
Go to the cloud console dashboard : https://console.cloud.google.com/home/dashboard
At the top, click on "Select a project" (looks like a drop down, but will open a modal UI)
In the popup, click on the "+" icon to the right to add a new project.
Enter a project name, e.g. "Cool Forum Google Login" (max 30 chars) and click "Create".
Note the ID (not the name) that's automatically assigned to the project. This will be useful
for going directly to that project's settings if you have multiple google projects. This ID
will be referred to as "projectID" in the following sections.

====generating a clientid & clientsecret====
Before we can get an oauth clientid, we must configure the project's OAuth consent screen (what
users will see before they allow your project their permission to access their userinfo).
Go to the OAuth consent screen page: https://console.cloud.google.com/apis/credentials/consent
(or https://console.cloud.google.com/apis/credentials/consent?project={projectID} if you already
had one or more existing google projects).
Fill in the required information and click "Save".

Now go to the Credentials page: https://console.cloud.google.com/apis/credentials
(Make sure that the project you created above is selected, or go directly to the project's
credentials page via https://console.cloud.google.com/apis/credentials?project={projectID} )
Click on "Create Credentials" and choose "OAuth client ID".
For Application type pick "Web application".
Important: For "Authorized JavaScript origins", put in your forum's domain without the path
or ending /. E.g. (https://www.my.site if your forum is at https://www.my.site/coolforum)
Click "Create".
Your client ID & secret will be shown in a popup. Store these somewhere safe. (If you lose
them, you can always get them back or regenerate new ones via the console)


===Enable GoogleLogin===
Log into your forum's AdminCP. (Upgrade to 5.4.2 if you haven't already)
Go to "Products & Hooks" > "Manage Products" and enable "Third Party Login - Google" if it's not already
enabled.
Click on the "Related Options: Enable Sign-in with Google" link to go to the options link.
In the options, Enable Sign-in with Google & enter in the client id & secret you created above in the
"Google OAuth Client ID" & "Google OAuth Client Secret", respectively.
Save the options.
