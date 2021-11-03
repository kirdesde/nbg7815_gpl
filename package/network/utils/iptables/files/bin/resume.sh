#!/bin/sh

. /etc/functions.sh
include /lib/config

config_load parental_monitor
config_get sent rule$1 sent 

if [ "$sent" -eq 1 ]; then
	echo "resume"
	uci set parental_monitor.rule$1.sent=0
	uci commit parental_monitor
	sync #This command is for emmc and ext4 filesystem
fi
