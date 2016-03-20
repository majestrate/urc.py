urc.py
======


What is URC?

URC stands for URC Relay Chat, protocol orginally created by d3v11.
URC is an NIH-inspired IRC-like protocol that uses optinally signed messages over tcp
connections in a broadcast like fashion, maybe it'll become routed using Kademlia later you never know.
No hub level authentication yet, maybe that will come later.
urc.py is a simple implementation of [urcd](https://github.com/JosephSWilliams/urcd/) that probably sucks less.

Requirements:

* tor browser running
* python 3.4 or higher


Install Requirements:

    # check out source code
    git clone https://github.com/majestrate/urc.py/
    cd urc.py

Basic Usage:

    # connect to the default hub on default port (psii2p655trtnvru.onion port 6789) via the default tor browser socks proxy ( 127.0.0.1 port 9150 )
    # binds irc server at 127.0.0.1 port 6667
    python3.4 urc.py
    # open up irc client and connect to server at 127.0.0.1
    # in irssi it's /connect 127.0.0.1
    # in hexchat it's /server 127.0.0.1

Direct connections:

    # to not use tor by default use the --no-socks flag
    python3.4 urc.py --no-socks --remote-hub urc.someplace.tld

Running A hub over tor:

    # append this to /etc/tor/torrc
    HiddenServiceDir /var/lib/tor/urc
    HiddenServicePort 6789 127.0.0.1:6789

your onion address will be in `/var/lib/tor/urc/hostname`

others can connect to your hub via `python3.4 urc.py --remote-hub=something.onion` given that `something.onion` is the onion address in `/var/lib/tor/urc/hostname`

Advanced usage:

    # establish a hub connection to <remote_hub_address> on port 6666
    # provide hub connection on port 6666 from <your_address>
    # connect with a socks proxy at 127.0.0.1 9050
    python3.4 urc.py --remote-hub <remote_hub_address> --remote-port 6666 --hub <your_address> --port 6666 --socks-port 9050 --socks-host 127.0.0.1
        

Connect to 127.0.0.1 port 6667 as irc server to talk to the network

To connect to many hubs at once add the flag `--hubs-file=/path/to/hubs.txt` where hubs.txt has the list of hubs you want to connect to

Other flags:

    --no-anon     # disable forced anon on local irc, doing so will affect anonymity
    --nick <name> # change the server name to irc.<name>.tld, doing so will affect anonymity

Log flags:

    --log debug   # spew out debug messages including raw log to stdout
    --log info    # less verbose log
    --log warn    # default log verbosity
    --log error   # least verbose log verbosity


active hubs:

* i2p.rocks:6789
* psii2p655trtnvru.onion:6789
* aq3ihmrjho3xqwbudzyioszdhrt6n6yox5kw3mwqkoy7it37b7ia.b32.i2p:6789
* also see [this](https://github.com/JosephSWilliams/urcd/tree/master/db/urchub) repo

"active" channels:

* #anonet
* #overchan



TODO:

* make irc ui better
* automagic PKI management ?
* configuration files ?
* manage public keys via irc ui ?
* manage toggling of drop rules via irc ui ?
* use json for pubkeys ?
* modularize ?
* ratelimiting ?

TODO IRC UI:

* implement TOPIC
* implement admin services
* add configurable filters
* implement remote user expiration

