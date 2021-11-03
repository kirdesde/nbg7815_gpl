#!/bin/sh

##FOR NBG7815
WIFI_DEV="wifi1"
WIFI_IFACE="ath0"

wifi_scheduling_up() {
  local iface_disabled=$(uci get wireless.$WIFI_IFACE.disabled)
  if [ "$iface_disabled" = "1" ]; then
    exit 0
  fi
  
  local chk_iface
  ([ -z "$(iwconfig $WIFI_IFACE 2> /dev/null)" ] || [ -n "$(iwconfig $WIFI_IFACE | grep "Not-Associated")" ]) && chk_iface="Not-Associated"
  if [ -n "$chk_iface" ]; then
    while true
    do
      if [ -f "/tmp/WirelessDev" ]; then
        local dev=$(cat /tmp/WirelessDev)
        if [ "$dev" = "$WIFI_DEV" ]; then
          break
        fi
        sleep 1
      else
        echo "$WIFI_DEV" > /tmp/WirelessDev
        /etc/init.d/wireless restart
        /sbin/macfilter "$WIFI_DEV"
        break
      fi
    done
  fi
}

wifi_scheduling_down() {
  /sbin/wifi down "$WIFI_DEV"
}

case $1 in
  up)
    wifi_scheduling_up
  ;;
  down)
    wifi_scheduling_down
  ;;
  *)
    echo 'error: invalid argument'
  ;;
esac