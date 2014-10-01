urc.py
======

Simple, less convoluted version of [https://github.com/d3v11b0t/urcd](urcd) that probably sucks less.


Work In progress

Usage:

    git clone https://github.com/majestrate/urc.py/
    cd urc.py/
    socat TCP-LISTEN:6661,bind=127.0.0.1,fork SOCKS4A:127.0.0.1:allyour4nert7pkh.onion.onion:6668,socksport=9050 & disown
    torify python3.4 urc.py 127.0.0.1 6667 127.0.0.1 6661
    echo '9df079de0e230028ddd2d1a34623fb280aa2ce81874971e2374e20305733fd85' >> pubkeys.txt


then connect to localhost as irc server

active channels:

* #overchan
* #anonet


this runs in read only mode, other nodes will not accept your messages unless they have your public key

TODO:

* automagic PKI management
* configuration files
* manage public keys via irc ui
* manage toggling of drop rules via irc ui
