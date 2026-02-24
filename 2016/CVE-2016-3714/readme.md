## just include the class and if imagick exists ... it'll blow out the policy.xml with a slightly modified ubuntu 14.04 base version w/ extra policies in place

Executing via puppet apply:
```
$ git clone https://github.com/jackdpeterson/imagick_secure_puppet.git
$ mv imagick_secure_puppet imagick_secure
$ sudo puppet apply --modulepath=. -e "include imagick_secure"
```

verify MD5 change

