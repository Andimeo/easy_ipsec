Easy IPSec
==========

# Overview

This project provides the ability to construct a simple and pure IPsec tunnel between gateways or servers by just a few trivial scripts and programs. There's no need to install common VPN software like OpenSwan, nor to make lots of configurations. All you need to do are only two steps, i.e., make some trivial settings and run a script in your local box. And that's it. You don't even need to worry about the connection drops, because the session is never going to expire. The encryption key is randomly generated and securely distributed when you run the script, and there will not be rekeying any more. So if you want higher security, just put the script into your crontab.

# Major features
* Supports Host-to-Host, Host-to-Site, Site-to-Site tunnels
* Supports AES-256 encryption
* Supports UDP encapsulation. The source/destination port numbers can be customized, which makes it possible to avoid some censor ACLs.

# Prerequisite

