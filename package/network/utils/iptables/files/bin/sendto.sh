#!/bin/sh

date=`date +%T`
echo $date

. /etc/functions.sh
include /lib/config
lock /tmp/.parental_monitor_mail.lock
config_load parental_monitor
config_get sent rule$1 sent 
account=$(uci get sendmail.mail_server_setup.account)
config_get start_hour rule$1 start_hour
config_get start_min rule$1 start_min
echo $start_hour
echo $start_min
config_get stop_hour rule$1 stop_hour
config_get stop_min rule$1 stop_min
echo $stop_hour
echo $stop_min

pre_limit_time=$(expr "$start_hour" \* 60 \+ "$start_min")
limit_time=$(expr "$stop_hour" \* 60 \+ "$stop_min")
now_hour=$(date +%H)
now_min=$(date +%M)
now_time=$(expr "$now_hour" \* 60 \+ "$now_min")

if [ "$sent" -eq 0 ] && [ $now_time -gt $pre_limit_time -a $now_time -lt $limit_time ]; then
	config_get mac_list rule$1 mac
	config_get email_list rule$1 email 
	echo $mac_list

	rules=`echo $mac_list | awk '{FS=" "} {print NF}'`
	i=1
	count=0
	least=0
	while [ "$i" -le "$rules" ]
	do
		mac=`echo $mac_list | awk '{FS=" "} {print $'$i'}'`
		echo $mac
		ip=`cat /proc/net/arp | grep "$mac" | awk -F ' ' '{ print $1}'`
		echo $ip
		if [ -n "$ip" ]; then
			count=`arping -I br-lan $ip -c 3 | wc -l`
			if [ "$count" -gt 3 ]; then
				least=$(( $least + 1 ))
			fi
		fi
		i=$(( $i + 1 ))
	done
		
	email_list_s=$(echo ${email_list//;/ })
	config_get username rule$1 mac_list
	if [ "$least" -gt 0 ]; then
		for email in $email_list_s
		do
			echo "sent"
			echo "From: Home Router <$account>" > /var/mail
			echo "To: $email" >> /var/mail
			echo "Subject: $username arrived home." >> /var/mail
			echo "Dear Parent," >> /var/mail
			echo "" >> /var/mail
			echo "	$username arrived home." >> /var/mail
			echo "" >> /var/mail
			echo "Best Regards" >> /var/mail
			sleep 1
			cat /var/mail | ssmtp -C /var/ssmtp.conf -v $email
		done
			uci set parental_monitor.rule$1.sent=1
			uci commit parental_monitor
		
	fi
fi
lock -u /tmp/.parental_monitor_mail.lock
