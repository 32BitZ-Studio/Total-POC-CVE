# CVE-2019-9081_poc
Poc for CVE-2019-9081, this CVE is just a new POP chain. The project is a pre-built vulnerable Laravel 5.7.x application with an entry point for POI vulnerability at URI /deserialize (POST-request).
## Lab setup:
Starting the vulnerable application:
```
$ git clone https://github.com/nth347/CVE-2019-9081_poc.git
$ cd CVE-2019-9081
$ php artisan serve
```
## Usage:
Obtaining payload:
```
$ php CVE-2019-8091_poc.php
```
Sending payload to the application using a POST request to URI /deserialize, via a parameter named data.
## Reference:
* [CVE-2019-9081](https://nvd.nist.gov/vuln/detail/CVE-2019-9081)
* [WisdomTree](https://laworigin.github.io/2019/02/21/laravelv5-7%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96rce/)
