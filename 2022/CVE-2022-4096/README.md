# CVE 2022 -4096

> Amine TITROFINE | January 21, 2023

--------------

This experiment is destinated to demonstrate how the DNS rebinding attack works on an emulated IoT.
In the setup, we have a simulated IoT device, which can be controlled through a web interface (this is typical
for many IoT devices). Many IoT devices do not have a strong protection mechanism, if attackers can
directly interact with them, they can easily compromise these devices.


# Environnement 
Host Machine :
    - This exploit has been experimented on (**Linux kali 6.0.0-kali5-amd64**), it can also be tested on (**Ubuntu**) distributions



# Exploit

## Containers commands and setup
First, clone this project in your local machine
```
$ git clone https://gitlab.com/grenoble-inp-ensimag/Secu3A/Devoir2/CVE_2022_4096_amine_titrofine_farah_ben_youssef_walid_lanjri.git
```

we access to the directory that contains the files of our repositroy

```
$ cd CVE_2022_4096_amine_titrofine_farah_ben_youssef_walid_lanjri
```

we start by building all the defined services in the (**docker-compose.yaml**) file
```
$ docker-compose build
```
And then, we ran the following command to start the different services
```
$ docker-compose up
```

## Configure the User VM

(**Step 1. Reduce Firefox’s DNS caching time:**)

```
network.dnsCacheExpiration: change its value to 0 (default is 60)
```
(**Step 2. Change /etc/hosts:**)

```
192.168.60.80 www.seedIoT32.com
```

(**Step 3. Local DNS Server:**)
we add the nameserver entry in the resolver configuration file
(/etc/resolv.conf). 

```
nameserver 10.9.0.53
```

## Testing the Lab Setup.
After configuring the User VM, use the dig command to get the IP address of www.attacker32.com. You should get 10.9.0.180 . If you do not get this, your lab environment is not set up correctly.

```
$ dig http://www.attacker32.com

```
##  Launch the Attack on the IoT Device

This part is well documented in the report, please refer to it starting from page (**17**).