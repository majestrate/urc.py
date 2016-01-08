urc.py
======


What is URC?

URC stands for URC Relay Chat, protocol orginally created by d3v11.
URC is an NIH-inspired IRC-like protocol that uses optinally signed messages over tcp
connections in a broadcast like fashion, maybe it'll become routed using Kademlia later you never know.
No hub level authentication yet, maybe that will come later.
urc.py is a simple implementation of [urcd](https://github.com/JosephSWilliams/urcd/) that probably sucks less.

Requirements:

* python 3.4
* libsodium
* python-libnacl

Install Requirements:

    # check out source code
    git clone https://github.com/majestrate/urc.py/
    cd urc.py/
    # get libnacl
    pip3 install --user libnacl

Basic Usage:

    # connect to main hub on default port
    python3.4 urc.py 

Direct connections:

    # to not use a socks proxy by default use the --no-socks flag
    python3.4 urc.py --no-socks --remote-hub urc.someplace.tld

Running A hub over tor:

    # append this to /etc/tor/torrc
    HiddenServiceDir /var/lib/tor/urc
    HiddenServicePort 6789 127.0.0.1:6789

your onion address will be in `/var/lib/tor/urc/hostname`

Advanced usage:

    # establish a hub connection to <remote_hub_address> on port 6666
    # provide hub connection on port 6666 from <your_address>
    # connect with a socks proxy at 127.0.0.1 9050
    python3.4 urc.py --remote-hub <remote_hub_address> --remote-port 6666 --hub <your_address> --port 6666 --socks-port 9050 --socks-host 127.0.0.1


Connect to 127.0.0.1 port 6667 as irc server to talk to the network

active hubs:

* see [this](https://github.com/JosephSWilliams/urcd/tree/master/db/urchub) repo

"active" channels:

* #anonet
* #overchan



TODO:

* make irc ui usable
* automagic PKI management
* configuration files
* manage public keys via irc ui
* manage toggling of drop rules via irc ui
* use json for pubkeys?
* modularize?
* ratelimiting

TODO IRC UI:

* implement TOPIC
* implement admin services
* add configurable filters
* implement remote user expiration

