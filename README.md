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

* libsodium
* libnacl
* python 3.4

Install Requirements:

    # check out source code
    git clone https://github.com/majestrate/urc.py/
    cd urc.py/

    # get submodules
    git submodule init
    git submodule update

    # install libsodium
    cd libsodium
    ./autogen.sh 
    make
    make install

    # install requirements
    sudo pip-3.4 install -r requirments.txt

Basic Usage:

    # connect to main hype hub on default port
    python3.4 urc.py --remote-hub fcc5:3cf4:d2db:8258:d9d1:f073:52fa:4b3

Advanced usage:

    # establish a hub connection to <remote_hub_address> on port 6666
    # provide hub connection on port 6666 from your hype address
    python3.4 urc.py --remote-hub <remote_hub_address> --remote-port 6666 --hub <your_hype_address> --port 6666



Connect to localhost as irc server to talk to the network
your public key is located in the motd of the server

active channels:

* #anonet
* #overchan

runs in read only mode, other nodes will not accept your messages unless they have your public key
add other's public keys in ./pubkeys.txt



TODO:

* make irc ui usable
* automagic PKI management
* configuration files
* manage public keys via irc ui
* manage toggling of drop rules via irc ui
* use json for pubkeys?
* modularize?

TODO IRC UI:

* implement TOPIC
* fix LIST
* fix MODE
* implement admin services
* fix channel joins
* add configurable filters
* implement remote user expiration

