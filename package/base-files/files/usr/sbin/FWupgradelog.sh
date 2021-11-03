#!/bin/sh
LOG_FILE="/tmp/ApplicationData/FWupgrade/FWupgrade.log"
LOG_FILE_ALT="/tmp/ApplicationData/FWupgrade/FWupgrade.log.1"

mkdir -p /tmp/ApplicationData/FWupgrade/

if [ "$1" != "" ]; then
	timestamp=$(date +%Y/%m/%d-%H:%M:%S)

	# log file not exists
	if [ ! -f $LOG_FILE ]; then
		echo "[$timestamp] $1" > $LOG_FILE
	else
		# log file exists, count line of log file first
		line_count=$(wc -l $LOG_FILE | cut -f1 -d' ')

		if [ $line_count -gt 200 ]; then
			mv $LOG_FILE $LOG_FILE_ALT
			echo "[$timestamp] $1" > $LOG_FILE
		else
			echo "[$timestamp] $1" >> $LOG_FILE
		fi
	fi
fi

exit 0
