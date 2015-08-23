urc.py
======


What is URC?

URC stands for URC Relay Chat, protocol orginally created by d3v11.
URC is an NIH-inspired IRC-like protocol that uses optinally signed messages over tcp
connections in a broadcast like fashion, maybe it'll become routed using Kademlia later you never know.
No hub level authentication yet, maybe that will come later.
urc.py is a simple implementation of [urcd](https://github.com/d3v11b0t/urcd) that probably sucks less.

Work In progress.

Requirements:

* python 3.4
* libnacl

Install Requirements:

    # check out source code
    git clone https://github.com/majestrate/urc.py/
    cd urc.py/
    # get libnacl
    pip3 install --user libnacl

Basic Usage:

    # connect to main hub on default port
    python3.4 urc.py 

Advanced usage:

    # establish a hub connection to <remote_hub_address> on port 6666
    # provide hub connection on port 6666 from your_address
    python3.4 urc.py --remote-hub <remote_hub_address> --remote-port 6666 --hub <your_address> --port 6666


Connect to ::1 as irc server to talk to the network

active hubs:

* allyour4nert7pkh.onion
* cbadanhgoo6oamul.onion
* freeanonine7mgki.onion

active channels:

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

