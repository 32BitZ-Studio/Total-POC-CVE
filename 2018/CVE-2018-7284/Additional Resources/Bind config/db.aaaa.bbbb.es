$TTL    120
@       IN      SOA     ns1.aaaaaaaaaaaa.bbbbbbbbbbbb.es.  admin.aaaaaaaaaaaa.bbbbbbbbbbbb.es. (
                  5       ; Serial
             604800     ; Refresh
              86400     ; Retry
            2419200     ; Expire
             604800 )   ; Negative Cache TTL
;
; name servers - NS records
     IN      NS      ns1.aaaaaaaaaaaa.bbbbbbbbbbbb.es.

; name servers - A records
ns1.aaaaaaaaaaaa.bbbbbbbbbbbb.es.          IN      A       192.168.171.200

;  A records
test.asterisk.0123456789.aaaaaaaaaaaa.bbbbbbbbbbbb.es.     IN      A      192.168.171.201
check.compress.0123456789.aaaaaaaaaaaa.bbbbbbbbbbbb.es.    IN      A      192.168.171.202
