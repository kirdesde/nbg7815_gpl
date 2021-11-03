#!/bin/sh

https_port=$(uci get firewall.remote_https.port)

ssh_iface=$(uci get firewall.remote_ssh.interface)
if [ "$ssh_iface" != "0" ]; then
  ssh_port=$(uci get firewall.remote_ssh.port)
fi

ftp_enable=$(uci get proftpd.global.enable)
if [ "$ftp_enable" == "1" ]; then
  ftp_port=$(uci get proftpd.global.port)
fi

wol_enable=$(uci get wol.main.enabled)
if [ "$wol_enable" == "1" ]; then
  wol_port=$(uci get wol.main.port)
fi

printer_server="9100"

#local www_port=$(uci get firewall.remote_www.port)              #web server uses https port.
#local telnet_port=$(uci get firewall.remote_telnet.port)        #NBG project does not support telnet.
#local microsoft_ds="445"                                        #It is used by NBG6817.
#local oneconnect_APP="263"                                      #It is used by NBG6817.
#local twonky="9000 9191"                                        #It is used by NBG6817.
#local browser_block_port="1 7 9 11 13 15 17 19 25 37 42 43 53 77 79 87 95 101 102 103 104 109 110 111 113 115 117 119 123 135 139 143 179 389 465 512 513 514 515 526 530 531 532 540 556 563 587 601 636 993 995 2049 4045 6000"

port_values="$printer_server"
for port_value in $https_port $ftp_port $wol_port $ssh_port
do
   if [ "$port_value" == "" ]; then
     port_values="$port_values"
   else
     port_values="$port_values $port_value"
   fi
done

echo -n "$port_values" > /tmp/system_port
echo -n "$port_values" > /tmp/system_using_port

port=$(netstat -lptun | awk '{print $4}')
for i in $port
do
        port_catch=$(echo $i |sed 's/:/ /g')
        last_port=$(echo $port_catch | awk '{print $NF}')
        if echo $last_port | grep -q '^[0-9]\+$'; then
                used_port=$(cat /tmp/system_port)
                port_flag=0
                for j in $used_port
                do
                        if [ $j -eq $last_port ]; then
                           port_flag=1
                        fi
                done
                if [ $port_flag -eq 0 ]; then
                        echo -n " $last_port" >> /tmp/system_port
                        echo -n " $last_port" >> /tmp/system_using_port
                fi
        fi
done


NAT_RuleCount=$(uci get nat.general.rules_count)
for i in $(seq 1 1 $NAT_RuleCount)
do
        Ex_port=$(uci get nat.rule$i.local_port)
        for j in $(echo $Ex_port | sed 's/,/ /g')
        do
                if [ $(echo $j |grep "-") ];then
                        if [ $(echo $j | awk -F '-' '{print $1}') -le $(echo $j | awk -F '-' '{print $2}') ];then
                                for k in $(seq $(echo $j | awk -F '-' '{print $1}') 1 $(echo $j | awk -F '-' '{print $2}'))
                                do
                                        echo -n " $k" >> /tmp/system_port
                                done
                        else
                                for k in $(seq $(echo $j | awk -F '-' '{print $2}') 1 $(echo $j | awk -F '-' '{print $1}'))
                                do
                                        echo -n " $k" >> /tmp/system_port
                                done
                        fi
                else
                        echo -n " $j" >> /tmp/system_port
                fi

        done
done

