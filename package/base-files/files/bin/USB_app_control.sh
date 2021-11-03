#!/bin/sh
tmpPath="/tmp/"
action=""
daemon=""
tmpFilePath=""
MAX_COUNT="2"

set_comm_value(){
	if [ "$1" == "" ]; then
		action="reload"
		daemon="$(cat /tmp/USB_app_control)"
	else
		action="$1"
		daemon="$2"
	fi
	tmpFilePath="$tmpPath""$daemon""_flag"
}

chk_flag(){
	if [ "$action" == "reload" ]; then
		flag_increase
		local val="$(cat $tmpFilePath)"
		if [ "$val" == "1" ]; then
			/etc/init.d/"$daemon" reload
		else
			exit
		fi
	elif [ "$action" == "end" ]; then
		flag_decrease
	fi
}

flag_increase(){
	if [ -f "$tmpFilePath" ]; then
		local val="$(cat $tmpFilePath)"
		if [ "$val" == "$MAX_COUNT" ]; then
			echo "$MAX_COUNT" > "$tmpFilePath"
		else
			val=`expr $val + 1`
			echo "$val" > "$tmpFilePath"
		fi
	else
		echo "1" > "$tmpFilePath"
	fi
}

flag_decrease(){
	if [ -f "$tmpFilePath" ]; then
		local val="$(cat $tmpFilePath)"
		val=`expr $val - 1`
		echo "$val" > "$tmpFilePath"
		if [ "$val" == "0" ]; then
			rm "$tmpFilePath"
		elif [ "$val" -ge "0" ]; then
			/etc/init.d/"$daemon" reload	
		fi
	fi
}

case "$1" in
	reload|end|"")
		### /bin/USB_app_control.sh reload/end samba/dlna/proftpd
		set_comm_value "$@"
		chk_flag
	;;

esac
exit 0
