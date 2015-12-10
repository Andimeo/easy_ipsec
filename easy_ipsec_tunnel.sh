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

UDP_ENCAP=
UDP_ENCAP_REVERSE=
if [ "$8" != "" ]; then
    LOCAL_PORT=$(echo $8 | awk ':' '{print $1}')
    REMOTE_PORT=$(echo $8 | awk ':' '{print $2}')
    if [ "$LOCAL_PORT" != "" ] && [ "$REMOTE_PORT" != "" ]; then
        UDP_ENCAP="encap espinudp $LOCAL_PORT $REMOTE_PORT 0.0.0.0"
        UDP_ENCAP_REVERSE="encap espinudp $REMOTE_PORT $LOCAL_PORT 0.0.0.0"
    fi
fi

KEY1=0x`dd if=/dev/urandom count=32 bs=1 2> /dev/null| xxd -p -c 64`
KEY2=0x`dd if=/dev/urandom count=32 bs=1 2> /dev/null| xxd -p -c 64`
ID=0x`dd if=/dev/urandom count=4 bs=1 2> /dev/null| xxd -p -c 8`

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
        cmd="sudo ip route add $2 dev $3"
        if [[ "$1" == */32 ]]; then
            # remove suffix /32
            cmd="$cmd src ${1%/32}"
        fi
        echo "$cmd;"
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
    sudo ip xfrm state add src $LOCAL_PUBLIC_IP dst $REMOTE_PUBLIC_IP proto esp spi $ID reqid $ID mode tunnel auth sha256 $KEY1 enc aes $KEY2 $UDP_ENCAP
    sudo ip xfrm state add src $REMOTE_PUBLIC_IP dst $LOCAL_PUBLIC_IP proto esp spi $ID reqid $ID mode tunnel auth sha256 $KEY1 enc aes $KEY2 $UDP_ENCAP_REVERSE
    sudo ip xfrm policy add src $REMOTE_NETWORK dst $LOCAL_NETWORK dir out tmpl src $REMOTE_PUBLIC_IP dst $LOCAL_PUBLIC_IP proto esp reqid $ID mode tunnel
    sudo ip xfrm policy add src $LOCAL_NETWORK dst $REMOTE_NETWORK dir in tmpl src $LOCAL_PUBLIC_IP dst $REMOTE_PUBLIC_IP proto esp reqid $ID mode tunnel
    sudo ip xfrm policy add src $LOCAL_NETWORK dst $REMOTE_NETWORK dir fwd tmpl src $LOCAL_PUBLIC_IP dst $REMOTE_PUBLIC_IP proto esp reqid $ID mode tunnel
    $(ip_cleaning_commands $REMOTE_NETWORK $LOCAL_NETWORK $REMOTE_IFACE)
    $(ip_creation_commands $REMOTE_NETWORK $LOCAL_NETWORK $REMOTE_IFACE $LOCAL_IFACE)
EOF

# set local
sudo ip xfrm state add src $LOCAL_PUBLIC_IP dst $REMOTE_PUBLIC_IP proto esp spi $ID reqid $ID mode tunnel auth sha256 $KEY1 enc aes $KEY2 $UDP_ENCAP
sudo ip xfrm state add src $REMOTE_PUBLIC_IP dst $LOCAL_PUBLIC_IP proto esp spi $ID reqid $ID mode tunnel auth sha256 $KEY1 enc aes $KEY2 $UDP_ENCAP_REVERSE
sudo ip xfrm policy add src $LOCAL_NETWORK dst $REMOTE_NETWORK dir out tmpl src $LOCAL_PUBLIC_IP dst $REMOTE_PUBLIC_IP proto esp reqid $ID mode tunnel
sudo ip xfrm policy add src $REMOTE_NETWORK dst $LOCAL_NETWORK dir in tmpl src $REMOTE_PUBLIC_IP dst $LOCAL_PUBLIC_IP proto esp reqid $ID mode tunnel
sudo ip xfrm policy add src $REMOTE_NETWORK dst $LOCAL_NETWORK dir fwd tmpl src $REMOTE_PUBLIC_IP dst $LOCAL_PUBLIC_IP proto esp reqid $ID mode tunnel
eval $(ip_creation_commands $LOCAL_NETWORK $REMOTE_NETWORK $LOCAL_IFACE $REMOTE_IFACE)
