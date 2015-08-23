URC is a decentralized chat protocol aimed as a replacement for IRC.

The first field is a 16bit length (LEN) in network byte order. While 16bit LEN can represent 65535 bytes of data the MTU of URC is 1024 bytes, or one kilobyte. The second field of URCHUB is taia96n, a 12 byte timestamp in network byte order that is accurate to nano seconds. The third field is a 32bit CMD and is currently used to distinguish types of packets. The last 24 bits of CMD SHOULD remain NULL until future usages are necessary. The fourth field are 64bits of random data that ensures uniqueness of a packet. The fifth field is the payload and it's size MUST be reflected by the 16bit LEN field. Generally this field is a URCLINE, but can also contain binary or alternative data.


    # basic urc packet header
    | 2 bytes length | 12 byte timestamp | 4 bytes message type | 8 bytes random | $URCLINE
    
    # by default the message type is all zeros
    # a urcline is similar to the line of IRC

    :nick!user@host PRIVMSG #channel :message goes here\n
    :nick!user@host NOTICE #channel :notice goes here\n
    :nick!user@host TOPIC #channel :topic goes here\n

also see the original protocol spec [here](http://anonet2.biz/URC)
