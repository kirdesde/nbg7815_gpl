#!/bin/sh

get_primaryboot() {
	if [ -f /tmp/zyxel_primaryboot ]; then
		echo $(cat /tmp/zyxel_primaryboot)
	else
		echo $(cat /proc/boot_info/rootfs/primaryboot)
	fi
	return 0
}

get_primary_header_partition() {
	local primaryboot
	primaryboot=$(get_primaryboot)
	if [ $primaryboot -eq 0 ]; then
		echo $(find_mmc_part header)
	else
		echo $(find_mmc_part header_1)
	fi
	return 0
}

get_zld_primaryboot() {
	if [ -f /tmp/zyxel_zld_primaryboot ]; then
		echo $(cat /tmp/zyxel_zld_primaryboot)
	else
		echo $(cat /proc/boot_info/0:APPSBL/primaryboot)
	fi
	return 0
}
