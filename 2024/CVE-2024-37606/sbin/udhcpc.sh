#!/bin/sh
#
# udhcpc script, v1.00 2009-11-05 andy
#

[ -z "$1" ] && echo "Error: should be called from udhcpc" && exit 1

RESOLV_CONF="/etc/resolv.conf"
[ -n "$broadcast" ] && BROADCAST="broadcast $broadcast"
[ -n "$subnet" ] && NETMASK="netmask $subnet"

case "$1" in
    deconfig)
#       /sbin/ifconfig $interface 0.0.0.0     #don't clear to 0, leave it to be config ip

        ;;

    bound)
        # change dhcp state
        gpio dhcpstate 2
        killall -q zcip
        ifconfig br0:0 down
        gpio autoip 0.0.0.0

        /sbin/ifconfig $interface $ip $BROADCAST $NETMASK

        if [ -n "$router" ] ; then
            echo "deleting route"
            while route del default gw 0.0.0.0 dev $interface ; do
                :
            done
            gpio gw 0.0.0.0

            metric=0
            for i in $router ; do
                metric=`expr $metric + 1`
                route add default gw $i dev $interface metric $metric
            done
            gpio gw $i
        fi

        echo -n > $RESOLV_CONF
        [ -n "$domain" ] && echo search $domain >> $RESOLV_CONF
        idx="1"
        for i in $dns ; do
            echo adding dns $i
            echo nameserver $i >> $RESOLV_CONF
            if [ $idx = "1" ]; then
               gpio dns1 0.0.0.0
               gpio dns1 $i
               idx="2"
            elif [ $idx = "2" ]; then
               gpio dns2 0.0.0.0
               gpio dns2 $i
               idx="3"
            fi            
        done

        if [ $idx = "1" ]; then
            pd=`nvram_get 2860 DNSIPAddress1`
            sd=`nvram_get 2860 DNSIPAddress2`
            if [ "$pd" != "" ]; then
                echo -n > $RESOLV_CONF
                echo nameserver $pd >> $RESOLV_CONF
                gpio dns1 0.0.0.0
                gpio dns1 $pd
            fi
            if [ "$sd" != "" ]; then
                echo nameserver $sd >> $RESOLV_CONF
                gpio dns2 0.0.0.0
                gpio dns2 $sd
            fi
        elif [ $idx = "2" ]; then
            pd=`nvram_get 2860 DNSIPAddress1`
            if [ "$pd" != "" ]; then
                echo nameserver $pd >> $RESOLV_CONF
                gpio dns2 0.0.0.0
                gpio dns2 $pd
            fi
        fi

        # ddns
        ddns.sh

        # upnp
        #upnp=`nvram_get 2860 UPnPEnable`
        #if [ "$upnp" = "1" ]; then
        route add -net 239.0.0.0 netmask 255.0.0.0 dev br0
        killall -q udev
        killall -q ucp
        udev &
        ucp &
        #fi

        # ntp
        ntp.sh

        # schedule for mail and ftp client
        killall -q schedule
        killall -q mail
        killall -q ftpputimage
        schedule &

        # udp configuration and tftp upload
        killall -q lanconfig
        killall -q tftpupload
        lanconfig &
        tftpupload &
        
        # mydlinkevent
        killall -q mydlinkevent
        mydlinkevent &

        # mDNSResponder
        killall -q mDNSResponder
        gpio mDNSResponder       

        # mydlink
        #/mydlink/opt.local stop
        #/mydlink/opt.local start
        echo "from udhcpc.sh"
        gpio mydlink
        
        # web server alphapd
        # killall -q alphapd
        # alphapd &
        web.sh        

        ;;
esac

exit 0

