#!/bin/sh
[ -z "$1" ] && echo "Error: should be run by udhcpc" && exit 1
 
case "$1" in
	deconfig)
		/sbin/ifconfig $interface 0.0.0.0
	;;
	renew|bound)
		echo "udhcpc: ifconfig $interface $ip netmask ${subnet:-255.255.255.0} broadcast ${broadcast:-+}"
		ifconfig $interface $ip netmask ${subnet:-255.255.255.0} broadcast ${broadcast:-+}

		[ -n "$router" ] && [ "$router" != "0.0.0.0" ] && [ "$router" != "255.255.255.255" ] && {
			while route del default gw 0.0.0.0 dev $interface ; do
			:
			done

			for i in $dns ; do
				if [ "$i" == "$router" ];then
					continue
				fi
				route add $i gw $router dev $interface
			done
		}
	;;
esac
 
exit 0