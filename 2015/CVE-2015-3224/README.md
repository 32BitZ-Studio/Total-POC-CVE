# CVE-2015-3224
## Ruby-On-Rails Web Console RCE

# What is this?
This is a metasploit module for Metasploit.

# I already have this module.
Yes, this is packaged into metasploit. But with that module you can't get arbitrary command execution.

I mean, you can only establish reverse/bind shell payloads with it. I needed to execute commands right to the shell. So I modified the metasploit module in a manner that it is now able to execute single commands into the system.

# Good. How do I use it?
To install this module you can run the automatic installation script I developed to install it quickly to your metasploit.
```bash
./install.sh
```

Then the exploit will be into your metasploit framework! Just search for it using "search ruby-on-rails" or "search cve-2015-3224"

# Screenshot
![Module](img/screenshot.JPG?raw=true)

# Author Rights
I got no rights to this CVE neither to the metasploit module itself. This is just a hack I've done it so it can fit into my needs and may be just what you have been looking for.
