Easy IPSec
==========

## Overview

This project provides the ability to construct a simple and pure IPsec tunnel between gateways or hosts by just a few trivial scripts. There's no need to install common VPN software like OpenSwan, nor to make lots of configurations. All you need to do are only two steps, i.e., make some trivial settings and run a script in your local box. And that's it. You don't even need to worry about the connection drops, because the session is never going to expire. The encryption key is randomly generated and securely distributed when you run the script, and there will not be rekeying any more. So if you want higher security, just put the script into your crontab.

Most of the steps in this document are under CentOS6. You may need to do some minor changes for some commands or paths under other distribution such as Ubuntu.

## Features

* Supports Host-to-Host, Host-to-Site, Site-to-Site tunnels.
* Supports AES-256 encryption and SHA256 authentication.
* No IKE style handshaking, no heart-beating. Thus, no chances to be interrupted by censorship.
* Supports both ESP and ESP-IN-UDP encapsulation. In additon, the UDP source/destination port numbers *CAN* be customized, which makes it possible to avoid being blocked by some advanced censorship ACLs.

## Prerequisite

* Two linux boxes with kernel 2.6+ which has introduced XFRM framework.
* Now both of the two boxes need to have public IPs. (Will provide NAT-T support later, then only remote box needs to have public IP)
* Has root account or other account with sudo privileges on two boxes.
* Has permission to ssh from local box into remote one.

## Prepare

1.  Setup accounts on both boxes:
  * for local box, it is quite straightful. You can use either root or an account with sudo privileges. Here we assume it `root`.
  * for remote box, you can use either root or account with sudo privileges. But since root login is usually forbidden in sshd config, it is recommended to choose the latter. Here we assume you use privileged user `remote_user`. In this case, you need to comment out `Defaults requiretty` in `/etc/suoders` to allow sudo commands via SSH.
  * Optionally, you can put `root`'s public key into `remote_user`'s `.ssh/authorized_keys` for a non-password ssh login. And you can make `remote_user` sudoable without password by replacing `remote_user`'s line into `remote_user ALL=(ALL) NOPASSWD: ALL` in `/etc/sudoers`. These two steps are especially useful if you want to create a cron job to periodically reconstruct the tunnel. But be careful about your accounts.

2.  Allow IP forwarding on gateways. No need for Host-to-Host tunnel.
  1. update `net.ipv4.ip_forward = 1` in `/etc/sysctl.conf`
  2. run `sysctl -p` to load the config file.

3.  Setup iptables.
  * Basically, you need rules to allow ESP traffic or specified UDP (if you choose UDP encapsulation) traffic to pass:
  ```
  iptables -A INPUT -p esp -m esp -j ACCEPT
  iptables -A INPUT -p udp -m udp --dport <given_port_number> -j ACCEPT
  ```
  * For gateway, it is recommended to add following rule to limit the path MTU in case the hosts or sites behind it disallow ICMP traffic to get through their firewalls:
  ```
  iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1398
  ```
