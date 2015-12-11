#!/bin/bash
#
# Some extra steps before running this script:
#
# 1. Need ssh permission on remote server, it is strongly recommended to put local public key on remote's authorized_keys.
# 2. Add ssh user for remote server into /etc/sudoers and comment out "Defaults requiretty", if you use a user rather than root.
# 3. Need local to enable ip_forward:
#    update "net.ipv4.ip_forward = 1" in /etc/sysctl.conf, then run "sudo sysctl -p"
# 4. Need remote to enable ip_forward too, and add two iptables rules:
#    iptables -A INPUT -p esp -m esp -j ACCEPT
#

if [ "$7" == "" ]; then
    echo "Usage: $0 <local_public_ip> <remote_public_ip> <local_network> <remote_network> <local_interface> <remote_interface> <remote_username> [<local_udp_port:remote_udp_port>]"
    echo "Examples (assuming eth0 for private subnet, eth1 for public network):"
    echo "  host-to-host (ESP): $0 61.135.100.3 52.59.100.5 10.0.0.1 10.0.0.2 eth0 eth0 remote_user"
    echo "  host-to-site (ESP): $0 61.135.100.3 52.59.100.5 10.0.0.1 172.16.1.0/24 eth0 eth1 remote_user"
    echo "  site-to-site (ESP): $0 61.135.100.3 52.59.100.5 192.168.1.0/24 172.16.1.0/24 eth1 eth1 remote_user"
    echo "  site-to-site (UDP): $0 61.135.100.3 52.59.100.5 192.168.1.0/24 172.16.1.0/24 eth1 eth1 remote_user 4500:4500"
    exit 1
fi

function fix_prefix()
{
    if [[ "$1" != */* ]]; then
        echo $1/32
    else
        echo $1
    fi
}

LOCAL_PUBLIC_IP="$1"
REMOTE_PUBLIC_IP="$2"
LOCAL_NETWORK=$(fix_prefix $3)
REMOTE_NETWORK=$(fix_prefix $4)
LOCAL_IFACE="$5"
REMOTE_IFACE="$6"
SSH_USER_HOST="$7@$REMOTE_PUBLIC_IP"

LOCAL_UDP_PORT=
REMOTE_UDP_PORT=
if [ "$8" != "" ]; then
    LOCAL_UDP_PORT=$(echo $8 | awk -F':' '{print $1}')
    REMOTE_UDP_PORT=$(echo $8 | awk -F':' '{print $2}')
fi

KEY1=0x`dd if=/dev/urandom count=32 bs=1 2> /dev/null| xxd -p -c 64`
KEY2=0x`dd if=/dev/urandom count=32 bs=1 2> /dev/null| xxd -p -c 64`
ID=0x`dd if=/dev/urandom count=4 bs=1 2> /dev/null| xxd -p -c 8`

# params: $1 local_public_ip, $2 remote_public_ip, $3 local_network, $4 remote_network, $5 local_udp_port, $6 remote_udp_port
function xfrm_creation_commands()
{
    if [ "$5" != "" ] && [ "$6" != "" ]; then
        echo "sudo ip xfrm state add src $1 dst $2 proto esp spi $ID reqid $ID mode tunnel auth sha256 $KEY1 enc aes $KEY2 encap espinudp $5 $6 0.0.0.0;"
        echo "sudo ip xfrm state add src $2 dst $1 proto esp spi $ID reqid $ID mode tunnel auth sha256 $KEY1 enc aes $KEY2 encap espinudp $6 $5 0.0.0.0;"
    else
        echo "sudo ip xfrm state add src $1 dst $2 proto esp spi $ID reqid $ID mode tunnel auth sha256 $KEY1 enc aes $KEY2;"
        echo "sudo ip xfrm state add src $2 dst $1 proto esp spi $ID reqid $ID mode tunnel auth sha256 $KEY1 enc aes $KEY2;"
    fi
    echo "sudo ip xfrm policy add src $3 dst $4 dir out tmpl src $1 dst $2 proto esp reqid $ID mode tunnel;"
    echo "sudo ip xfrm policy add src $4 dst $3 dir in tmpl src $2 dst $1 proto esp reqid $ID mode tunnel;"
    echo "sudo ip xfrm policy add src $4 dst $3 dir fwd tmpl src $2 dst $1 proto esp reqid $ID mode tunnel;"
}

# params: $1 local_network, $2 remote_network, $3 local_iface
function ip_cleaning_commands()
{
    if [[ "$1" == */32 ]]; then
        echo "sudo ip addr del $1 dev $3;"
    fi
    if [[ "$2" != */0 ]]; then
        echo "sudo ip route del $2;"
    fi
}

# params: $1 local_network, $2 remote_network, $3 local_iface, $4 remote_iface
function ip_creation_commands()
{
    if [[ "$1" == */32 ]]; then
        echo "sudo ip addr add $1 dev $3;"
    fi
    if [[ "$2" != */0 ]]; then
        cmd="sudo ip route add $2 dev $3 initcwnd 10"
        if [[ "$1" == */32 ]]; then
            # remove suffix /32
            cmd="$cmd src ${1%/32}"
        fi
        echo "$cmd;"
    fi
}

# param: $1 local_udp_port
function udp_daemon_commands()
{
    EXE=udp_daemon.py
    if [ "$LOCAL_UDP_PORT" != "" ] && [ "$REMOTE_UDP_PORT" != "" ]; then
        echo "ps x | grep $EXE | grep -v grep | awk '{print \$1}' | xargs --no-run-if-empty sudo kill -9;"
        echo "echo '#!/usr/bin/python' > $EXE;"
        echo "echo 'import socket, time' >> $EXE;"
        echo "echo 's = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)' >> $EXE;"
        # UDP_ENCAP=100, UDP_ENCAP_ESPINUDP=2
        echo "echo 's.setsockopt(socket.IPPROTO_UDP, 100, 2)' >> $EXE;"
        echo "echo \"s.bind(('0.0.0.0', $1))\" >> $EXE;"
        echo "echo 'while True:' >> $EXE;"
        echo "echo '    time.sleep(86400)' >> $EXE;"
        echo "nohup sudo python ./$EXE 2>/dev/null 1>&2 &"
    fi
}

# clean up local setting, this should be done before connecting to remote
sudo ip xfrm state flush
sudo ip xfrm policy flush
eval $(ip_cleaning_commands $LOCAL_NETWORK $REMOTE_NETWORK $LOCAL_IFACE)

# set remote
ssh $SSH_USER_HOST /bin/bash << EOF
    sudo ip xfrm state flush
    sudo ip xfrm policy flush
    $(xfrm_creation_commands $REMOTE_PUBLIC_IP $LOCAL_PUBLIC_IP $REMOTE_NETWORK $LOCAL_NETWORK $REMOTE_UDP_PORT $LOCAL_UDP_PORT)
    $(ip_cleaning_commands $REMOTE_NETWORK $LOCAL_NETWORK $REMOTE_IFACE)
    $(ip_creation_commands $REMOTE_NETWORK $LOCAL_NETWORK $REMOTE_IFACE $LOCAL_IFACE)
    $(udp_daemon_commands $REMOTE_UDP_PORT)
EOF

# set local
eval $(xfrm_creation_commands $LOCAL_PUBLIC_IP $REMOTE_PUBLIC_IP $LOCAL_NETWORK $REMOTE_NETWORK $LOCAL_UDP_PORT $REMOTE_UDP_PORT)
eval $(ip_creation_commands $LOCAL_NETWORK $REMOTE_NETWORK $LOCAL_IFACE $REMOTE_IFACE)
eval $(udp_daemon_commands $LOCAL_UDP_PORT)
