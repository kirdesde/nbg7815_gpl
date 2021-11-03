#!/bin/sh
	

	while true 
	do	
		
		order=$(iptables -L access_schedule_ex|grep -n rule$1|awk '{FS=":"} {print $1}'|sed -n '1p')
		if [ "$order" == "" ] ; then 
			break 
		fi
		order=$(($order-2))
		iptables -D access_schedule_ex $order
		
	done
	
	killall -9 crond

	i=0

	if [ -f /etc/crontabs/root ]&&[ "$i" == 0 ]; then
		i=1		
		sed -i -e '/reward.sh '$1'/d' /etc/crontabs/root
		uci delete parental_ex.rule"$1".reward_min
		uci delete parental_ex.rule"$1".timestamp
		uci commit parental_ex
		sync #This command is for emmc and ext4 filesystem
	fi

	crond -c /etc/crontabs	


