# CVE-2019-14287 Demo Container

This is a container built for demonstration purposes that has a version of 
the `sudo` command which is vulnerable to CVE-2019-14287
 (https://www.sudo.ws/alerts/minus_1_uid.html).
 
This container can be run with:

`docker run -ti cashwilliams/cve-2019-14287-demo`


## Configuration

The container has three real users:

- root
- alice
- bob

The alice user is configured to have the ability to run any command as any 
other user (in this case bob as it is the only other user) using 
`sudo -u(user) (command)`, however is restricted from running commands as 
root. This is configured in the `/etc/sudoers` file at the end using:

`alice ALL=(ALL,!root) NOPASSWD: ALL`

You can try to run commands as bob, such as opening a shell, with the 
following:

`sudo -ubob bash`

However, if you attempt to run a command as root, you will be prompted for 
a password which is unknown (and the command would fail anyway). This is by 
design and shows the sudo command working properly.

## CVE-2019-14287

The "minus_1_uid" bug within sudo (https://www.sudo.ws/alerts/minus_1_uid.html) 
was published on October 14, 2019 and demostrates an issue with how the user 
argument is interpreted.

In this case alice can run commands as the root user, such as opening a shell, 
with the following:

`sudo -u#-1 bash`

