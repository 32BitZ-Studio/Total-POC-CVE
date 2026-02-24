# CVE-2022-21724: JDBC RCE PostgreSQL 

## Intro
This demo will show how a non-patched JDBC driver can be used to attach PostgreSQL and gain RCE.

Affecting org.postgresql:postgresql package, versions [9.4.1208,42.2.25) [42.3.0,42.3.2)

This demo is deployed using Vagrant and will deploy the following nodes:

| Name | IP | Postgres | Remarks |
| -------- | -------- | ----- | -------- |
| attacker | 192.168.0.210 | -- | Metasploit Framework |
| vuln | 192.168.0.211 | 9.6.4 |  |
| novuln | 192.168.0.212 | 16.3 |  |

## Demo prep
### Pre-requisites
To deploy this demo the following needs to be installed in the PC from which you are going to deploy the demo:

- VirtualBox (https://www.virtualbox.org/)
- Vagrant (https://www.vagrantup.com/)
- Vagrant Hosts plug-in (`vagrant plugin install vagrant-hosts`)
- Vagrant Reload plug-in (`vagrant plugin install vagrant-reload`)

The environment is deloyed in a VirtualBox **public** network. Adjust the IP addresses to your needs in `vars.yml`.

### Provisioning VM's.
Provision the hosts using `vagrant up`. This will create the bare virtual machines and will take appx. 5 minutes to complete. 

After provisioning, the hosts will have the current directory mounted in their filesystem under `/vagrant`

### Passwords


## Demo flow
