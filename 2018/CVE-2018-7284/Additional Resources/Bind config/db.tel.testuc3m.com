;
; BIND data file for local loopback interface
;
$TTL	40
@	IN	SOA	pbx.tel.testuc3m.com. root.tel.testuc3m.com. (
			     33		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
;
@	IN	NS	pbx.tel.testuc3m.com.
@	IN	A	192.168.171.140
pbx	IN	A	192.168.171.141
www	IN	CNAME	tel.testuc3m.com.


_sip._udp.tel.testuc3m.com.	325	IN	SRV	10	0	5060	test.asterisk.0123456789.aaaaaaaaaaaa.bbbbbbbbbbbb.es.
_sip._udp.tel.testuc3m.com.	325	IN	SRV	20	0	5060	check.compress.0123456789.aaaaaaaaaaaa.bbbbbbbbbbbb.es.
