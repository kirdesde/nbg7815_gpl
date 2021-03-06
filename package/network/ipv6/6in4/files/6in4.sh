#!/bin/sh
# 6in4.sh - IPv6-in-IPv4 tunnel backend
# Copyright (c) 2010-2015 OpenWrt.org

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. /lib/functions/network.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

proto_6in4_update() {
	sh -c '
		local timeout=5

		(while [ $((timeout--)) -gt 0 ]; do
			sleep 1
			kill -0 $$ || exit 0
		done; kill -9 $$) 2>/dev/null &

		exec "$@"
	' "$1" "$@"
}

proto_6in4_setup() {
	local cfg="$1"
	local iface="$2"
	local link="6in4-$cfg"

	local mtu ttl tos ipaddr peeraddr ip6addr ip6prefix tunnelid username password updatekey
	json_get_vars mtu ttl tos ipaddr peeraddr ip6addr ip6prefix tunnelid username password updatekey

	local ck6in4Enable=$(uci get network.general."$cfg"_enable)
	[ "$ck6in4Enable" == "0" ] && return

	[ -z "$peeraddr" ] && {
		proto_notify_error "$cfg" "MISSING_ADDRESS"
		proto_block_restart "$cfg"
		return
	}

	( proto_add_host_dependency "$cfg" "$peeraddr" )

	[ -z "$ipaddr" ] && {
		local wanif
		if ! network_find_wan wanif || ! network_get_ipaddr ipaddr "$wanif"; then
			proto_notify_error "$cfg" "NO_WAN_LINK"
			return
		fi
	}

	proto_init_update "$link" 1

	[ -n "$ip6addr" ] && {
		local local6="${ip6addr%%/*}"
		local mask6="${ip6addr##*/}"
		[[ "$local6" = "$mask6" ]] && mask6=
		proto_add_ipv6_address "$local6" "$mask6"
		proto_add_ipv6_route "::" 0 "" "" "" "$local6/$mask6"
	}

	[ -n "$ip6prefix" ] && {
		proto_add_ipv6_prefix "$ip6prefix"
		proto_add_ipv6_route "::" 0 "" "" "" "$ip6prefix"
	}

	proto_add_tunnel
	json_add_string mode sit
	json_add_int mtu "${mtu:-1280}"
	json_add_int ttl "${ttl:-64}"
	[ -n "$tos" ] && json_add_string tos "$tos"
	json_add_string local "$ipaddr"
	json_add_string remote "$peeraddr"
	proto_close_tunnel

	proto_send_update "$cfg"

	[ -n "$tunnelid" -a -n "$username" -a \( -n "$password" -o -n "$updatekey" \) ] && {
		[ -n "$updatekey" ] && password="$updatekey"

		local http="http"
		local urlget="wget"
		local urlget_opts="-qO-"
		local ca_path="${SSL_CERT_DIR-/etc/ssl/certs}"

		if [ -n "$(which curl)" ]; then
			urlget="curl"
			urlget_opts="-s -S"
			if curl -V | grep "Protocols:" | grep -qF "https"; then
				http="https"
				urlget_opts="$urlget_opts --capath $ca_path"
			fi
		fi
		if [ "$http" = "http" ] &&
			wget --version 2>&1 | grep -qF "+https"; then
			urlget="wget"
			urlget_opts="-qO- --ca-directory=$ca_path"
			http="https"
		fi
		[ "$http" = "https" -a -z "$(find $ca_path -name "*.0" 2>/dev/null)" ] && {
			if [ "$urlget" = "curl" ]; then
				urlget_opts="$urlget_opts -k"
			else
				urlget_opts="$urlget_opts --no-check-certificate"
			fi
		}

		local url="$http://ipv4.tunnelbroker.net/nic/update?username=$username&password=$password&hostname=$tunnelid"
		local try=0
		local max=3

		(
			set -o pipefail
			while [ $((++try)) -le $max ]; do
				if proto_6in4_update $urlget $urlget_opts "$url" 2>&1 | \
					sed -e 's,^Killed$,timeout,' -e "s,^,update $try/$max: ," | \
					logger -t "$link";
				then
					logger -t "$link" "updated"
					return 0
				fi
				sleep 5
			done
			logger -t "$link" "update failed"
		)
	}

	##Add for assign LAN ipv6 address
	local ipv6lan=
	local ipv6lanold=$(uci get network."$cfg".zyipv6lan)
	local prefix_local6="${ip6prefix%%/*}"
	local prefix_mask6="${ip6prefix##*/}"

	local config_section=$(echo "$cfg"| sed s/6in4//g)
	local lanIface=
	[ "${cfg:0:3}" == "wan" ] && {
		lanIface=$(uci get network."$config_section".bind_LAN)
		lanIface=$(echo $lanIface | cut -c 4-)	
		[ -z "$lanIface" ] && lanIface=lan		
	}
	
	##add 6in4 CPE lan-ipv6 
	ipv6lan="$prefix_local6"1
	
	[ -n "$ipv6lanold" -a "$ipv6lanold" != "$ipv6lan" ] && ifconfig br-$lanIface del "$ipv6lanold"/64
	ifconfig br-$lanIface add "$ipv6lan"/64

	uci set network."$cfg".zyipv6lan=$ipv6lan
	uci commit network

	echo 1 > /tmp/radvd_6in4
	/etc/init.d/radvd restart
	##END	
}

proto_6in4_teardown() {
	local cfg="$1"
}

proto_6in4_init_config() {
	no_device=1
	available=1

	proto_config_add_string "ipaddr"
	proto_config_add_string "ip6addr"
	proto_config_add_string "ip6prefix"
	proto_config_add_string "peeraddr"
	proto_config_add_string "tunnelid"
	proto_config_add_string "username"
	proto_config_add_string "password"
	proto_config_add_string "updatekey"
	proto_config_add_int "mtu"
	proto_config_add_int "ttl"
	proto_config_add_string "tos"
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol 6in4
}
