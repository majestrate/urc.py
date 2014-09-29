#!/usr/bin/env python3.4
# 
# urc.py
#
# monolithic urc hub in python because urcd sucks ass
#
# public domain
#
import binascii
import struct
import asyncio
from random import randrange, Random
import time
import logging
import os
from hashlib import sha256
import libnacl

rand = lambda n : os.urandom(n)

# i don't like regular expressions
import re  

# -- begin lameass regexp block

_RE_CHARS = 'a-zA-Z0-9\.\\|\\-_~\\[\\]'
_CHAN_PREFIX = '&#+'
_RE_CHAN_PREFIX = '[%s]' % _CHAN_PREFIX
_RE_CHAN = '%s+[%s]+' % (_RE_CHAN_PREFIX, _RE_CHARS)
_RE_NICK = '[%s]+' % _RE_CHARS
_RE_SRC = '[%s]+![~%s]+@[%s]+' % ( (_RE_CHARS, ) * 3)
_RE_CMD = '[A-Z]+'
_RE_URCLINE = '^:(%s) (%s) ?(%s|%s)? ?:(.+)$' % (_RE_SRC, _RE_CMD, _RE_CHAN, _RE_NICK)

_RE_SRC_CMD = '([%s]+)!([~%s]+)@([%s]+)' % ( ( _RE_CHARS, ) * 3 )
_RE_NICK_CMD = '^NICK (%s)' % _RE_NICK
_RE_USER_CMD = '^USER (%s) [%s\\*]+ [%s\\*]+ :%s' % ( _RE_NICK, _RE_CHARS, _RE_CHARS, _RE_NICK )
_RE_PRIVMSG_CMD = '^PRIVMSG (%s|%s) :(.+)$' % (_RE_NICK, _RE_CHAN)
_RE_JOIN_CMD = '^JOIN (%s)' % _RE_CHAN
_RE_JOIN_MULTI_CMD = '^JOIN (.+)' 
_RE_PART_CMD = '^PART (%s) :(.+)$' % _RE_CHAN
_RE_QUIT_CMD = '^QUIT (.+)$'
_RE_LIST_CMD = '^LIST'
_RE_PING_CMD = '^PING (.*)$' 

# -- end lameass regexp block

# -- being crypto stuff

_SIG_SIZE = libnacl.crypto_sign_BYTES

def nacl_verify(m, s, pk):
    """
    verify message m with signature s for public key pk
    """
    libnacl.crypto_sign_open(s+m, pk)

def nacl_sign(m, sk):
    """
    sign message m with secret key sk
    return signature
    """
    s = libnacl.crypto_sign(m,sk)
    print(len(s) - len(m))
    return s[:_SIG_SIZE]


def test_crypto(data=rand(8)):
    pk , sk = libnacl.crypto_sign_keypair()
    sig = nacl_sign(data, sk)
    nacl_verify(data, sig, pk)

test_crypto()

def pubkey2bin(pk):
    return binascii.unhexlify(pk)

# -- end crypto stuff

# -- begin irc functions

def _irc_re_parse(regex, line):
    m = re.match(regex, line)
    if m:
        return m.groups()


def irc_is_chan(chan):
    for p in _CHAN_PREFIX:
        if chan[0] == p:
            return True
    return False

irc_parse_nick_user_serv = lambda line: _irc_re_parse(_RE_SRC_CMD, line)
irc_parse_channel_name = lambda line : _irc_re_parse(_RE_CHAN, line)
irc_parse_nick = lambda line : _irc_re_parse(_RE_NICK_CMD, line)
irc_parse_user = lambda line : _irc_re_parse(_RE_USER_CMD, line)
irc_parse_privmsg = lambda line : _irc_re_parse(_RE_PRIVMSG_CMD, line)
irc_parse_join = lambda line : _irc_re_parse(_RE_JOIN_CMD, line)
irc_parse_multi_join = lambda line : _irc_re_parse(_RE_JOIN_MULTI_CMD, line)
irc_parse_part = lambda line : _irc_re_parse(_RE_PART_CMD, line)
irc_parse_quit = lambda line : _irc_re_parse(_RE_QUIT_CMD, line)
irc_parse_ping = lambda line : _irc_re_parse(_RE_PING_CMD, line)

def irc_greet(serv, nick, user, motd):
    """
    generate an irc greeting for a new user 
    return a generator of lines to send 
    """
    for num , msg in (
            ('001', ':{}'.format(serv)), 
            ('002', ':{}!{}@{}'.format(nick,user,serv)),
            ('003', ':{}'.format(serv)),
            ('004', '{} 0.0 :+'.format(serv)),
            ('005', 'NETWORK={} CHANTYPES=#&!+ CASEMAPPING=ascii '
             'CHANLIMIT=25 NICKLEN=25 TOPICLEN=128 CHANNELLEN=16 COLOUR=1 UNICODE=1 PRESENCE=0:')):
        yield ':{} {} {} {}\n'.format(serv, num, nick, msg)
    yield ':{} 254 {} 25 :CHANNEL(s)\n'.format(serv, nick)
    yield ':{}!{}@{} MODE {} +i\n'.format(nick, user, serv, nick)
    yield ':{} 376 {} :- {} MOTD -\n'.format(serv, nick, serv)
    for line in motd:
        yield ':{} 372 {} :- {}\n'.format(serv, nick, line)
    yield ':{} 376 {} :RPL_ENDOFMOTD\n'.format(serv, nick)

# -- end irc functions

def taia96n():
    """
    get unnecessarily accurate time for now
    """
    now = time.time()
    sec = int(4611686018427387914) + int(now)
    nano = int(1000000000*(now%1)+randrange(0,512))
    return sec, nano

def taia96n_now():
    """
    get unnecessarily accurate timestamp for time right now
    """
    now = time.time()
    sec, nano = taia96n()
    return struct.pack('<QI', sec, nano)

def taia96n_parse(data):
    """
    parse unnecessarily accurate timestamp
    """
    if len(data) != 12: return None
    return struct.unpack('<QI',data)

def filter_urcline(string, filler=''):
    """
    filter undesirable characters out of urcline string
    """
    for bad in '\r\x00':
        string = string.replace(bad, filler)
    return string

def mk_urcline(src, cmd, dst, msg):
    """
    make a raw urcline given source, destination, command and message
    :return: utf-8 encoded bytes
    """
    src = filter_urcline_chars(src).strip()
    dst = filter_urcline_chars(dst).strip()
    cmd = filter_urcline_chars(cmd).upper()
    msg = filter_urcline_chars(msg)
    return ':{} {} {} :{}\n'.format(src, dst, cmd, msg).encode('utf-8')

def parse_urcline(line):
    """
    return (source, command, destination, message) tuple from URCLINE or None if invalid syntax
    """
    m = re.match(_RE_URCLINE, line)
    if m:
        return m.groups()

def mk_hubpkt(pktdata, pkttype=0):
    """
    make urc hub packet
    """
    data = bytes()
    pktlen = len(pktdata)
    if pkttype == 1:
        pktlen += _SIG_SIZE
    data += struct.pack('>H', pktlen) # packet length
    data += taia96n_now() # timestamp
    data += struct.pack('<I', pkttype) # packet type
    data += rand(8) # 64 bit random
    data += pktdata
    return data

class _log:
    
    def __init__(self):
        self.debug = self._logit
        self.info = self._logit
        self.warn = self._logit
        self.error = self._logit
    
    def _logit(self, *args):
        print ('>> ', *args)

def inject_log(obj, native_log=True):
    """
    inject logger object
    """
    log = None
    if native_log:
        log = logging.getLogger(obj.__class__.__name__)
    else:
        log = _log()
    obj.log = log

class urc_hub_connection:

    def __init__(self, urcd, r, w):
        self.urcd = urcd
        self.r, self.w = r, w
        inject_log(self)

    @asyncio.coroutine
    def get_hub_packet(self):
        """
        yield a hub packet tuple , (raw_packet, packet_data)
        """
        raw = bytes()
        data = yield from self.r.readexactly(2)
        pktlen = struct.unpack('>H', data)[0]
        raw += data
        data = yield from self.r.readexactly(12)
        tsec, tnano = taia96n_parse(data)
        raw += data
        data = yield from self.r.readexactly(4)
        pkttype = struct.unpack('<I', data)[0]
        raw += data
        data = yield from self.r.readexactly(8)
        self.log.debug('read packet len={}'.format(pktlen))
        raw += data
        data = yield from self.r.readexactly(pktlen)
        raw += data
        self.log.info('data={}'.format([data]))
        return raw, data, pkttype

    @asyncio.coroutine
    def send_hub_packet(self,pktdata):
        """
        send a hub packet
        pktdata must be bytes and a valid packet
        """
        self.log.info('send packet')
        self.log.info('write %d bytes' % len(pktdata))
        self.log.info('write %s' % [pktdata])
        self.w.write(pktdata)
        try:
            yield from self.w.drain()
        except Exception as e:
            self.log.error(e)
            self.urcd._disconnected(self)
        self.log.info('drained')
        

class irc_handler:
    """
    simple ircd ui logic
    """

    def __init__(self, urcd, r, w):
        self.urcd = urcd
        self.loop = urcd.loop
        self.r, self.w = r, w
        self.nick = None
        self.user = None
        self.greeted = False
        self.chans = list()
        inject_log(self)
        asyncio.async(self._get_line())

    @asyncio.coroutine
    def _get_line(self):
        line = yield from self.r.readline()
        if len(line) != 0:
            try:
                yield from self._handle_line(line)
            except Exception as e:
                self.log.error(e)
                self.urcd._disconnected(self)
                raise e
            else:
                asyncio.async(self._get_line())
   
    @asyncio.coroutine
    def change_nick(self, new_nick):
        line = ':{}!{}@{} NICK {}\n'.format(self.nick,self.user, self.urcd.name, new_nick)
        yield from self.send_line(line)
        self.nick = new_nick

    @asyncio.coroutine
    def send_line(self, line):
        """
        send a single line
        """
        self.w.write(line.encode('utf-8'))
        self.log.debug(' <-- {}'.format(line))
        yield from self.w.drain() 

    @asyncio.coroutine
    def _handle_line(self, line):
        """
        handle a line from irc client
        """
        line = line.decode('utf-8')
        line = filter_urcline(line)
        self.log.debug(' --> %s' %[line])
        _nick = irc_parse_nick(line)
        _user = irc_parse_user(line)
        _join = irc_parse_join(line)
        _joins = irc_parse_multi_join(line)
        _part = irc_parse_part(line)
        _quit = irc_parse_quit(line)
        _privmsg = irc_parse_privmsg(line)
        _ping = irc_parse_ping(line)
        
        # PING
        if _ping:
            yield from self.send_line(':{} PONG {}\n'.format(self.urcd.name, _ping[0]))
        # QUIT
        if _quit:
            yield from self.urcd.broadcast(':{}!{}@{} QUIT :quit\n'.format(self.nick, self.user, self.urcd.name))
            self.w.write_eof()
            self.w.transport.close()
            self.urcd._disconnected(self)
            return
        # NICK
        if self.nick is None and _nick is not None:
            self.nick = _nick[0]
        elif self.nick is not None and _nick is not None:
            yield from self.change_nick(_nick[0])
            
        # USER
        if self.user is None and _user is not None:
            self.user = _user[0]
        
        if self.greeted:
            # JOIN 
            self.log.debug(_joins)
            chans = list()
            if _joins:
                for chan in _joins[0].split(','):
                    self.log.debug(chan)
                    if irc_is_chan(chan):
                        chans.append(chan)
                        self.log.debug('multijoin {}'.format(chan))
            elif _join and _join[0] not in self.chans:
                chans.append(_join[0])

            for chan in chans:
                self.log.debug('join {}'.format(chan))
                if chan in self.chans:
                    self.log.debug('not joining {}'.format(chan))
                    continue
                self.chans.append(chan)
                line = ':{}!{}@{} JOIN {}\n'.format(self.nick, self.user, self.urcd.name, chan)
                asyncio.async(self.send_line(line))
                line = ':{} 353 {} = {} :{}\n'.format(self.urcd.name, self.nick, chan, self.nick)
                asyncio.async(self.send_line(line))
                line = ':{} 366 {} {} :RPL_ENDOFNAMES\n'.format(self.urcd.name, self.nick, chan)
                asyncio.async(self.send_line(line))
                
            # PART
            if _part and _part in self.chans:
                self.chans.remove(_part)
                line = ':{}!{}@{} PART {}\n'.format(self.nick, self.user, self.urcd.name, chan)
                asyncio.async(self.send_line(line))
            
            # PRVIMSG
            if _privmsg:
                dest, msg = _privmsg
                line = ':{}!{}@{} PRIVMSG {} :{}\n'.format(self.nick, self.user, 
                                                         self.urcd.name, dest, msg)
                chan = dest
                for irc_user in self.urcd.irc_cons:
                    self.log.debug(irc_user.nick)                        
                    self.log.debug(irc_user.chans)
                    if irc_user.nick != self.nick and chan in irc_user.chans:
                        asyncio.async(irc_user.send_line(line))
                    
                asyncio.async(self.urcd.broadcast(line))
        else:
            if self.nick is not None and self.user is not None:
                for line in irc_greet(self.urcd.name, self.nick, self.user, self.urcd.motd()):
                    yield from self.send_line(line)
                self.greeted = True

class _bloom_filter:
    """
    http://code.activestate.com/recipes/577684-bloom-filter/
    """

    def __init__(self, num_bytes, num_probes):
        self.array = bytearray(num_bytes)
        self.num_probes = num_probes
        self.num_bins = num_bytes * 8

    def get_probes(self, key):
        h = int(sha256(key).hexdigest(), 16)
        for _ in range(self.num_probes):
            yield h & 262143    # 2 ** 18 - 1
            h >>= 18

    def add(self,key):
        for i in self.get_probes(key):
            self.array[i//8] |= 2 ** (i%8)

    def __contains__(self, key):
        return all(self.array[i//8] & (2 ** (i%8)) for i in self.get_probes(key))

 
class URCD:
    """
    urcd server context
    """

    def __init__(self):
        self.initkeys()
        self.name = self.get_pubkey()[:16]
        self.hubs = list()
        self.persist_hubs = dict()
        self.irc_cons = list()
        self.irc_chans = dict()
        self.hooks = list()
        self.loop = asyncio.get_event_loop()
        self.tasks = list()
        self._urc_cache = _bloom_filter(32 * 1024, 4)
        inject_log(self)
        self.loop.call_later(1, self._persist_hubs)

    def get_pubkey(self):
        """
        get public key in base 32
        """
        return binascii.hexlify(self._pk).decode('ascii')

    def load_keys(self, fname):
        """
        load signing keys from file
        """
        with open(fname , 'rb') as f:
            self._pk = f.read(libnacl.crypto_sign_PUBLICKEYBYTES)
            self._sk = f.read(libnacl.crypto_sign_SECRETKEYBYTES)

    def dump_keys(self, fname):
        """
        dump signing keys to file
        """
        with open(fname, 'wb') as f:
            f.write(self._pk)
            f.write(self._sk)
        
        
    def initkeys(self, fname='keys.dat'):
        """
        generate / load signing keys
        """
        if not os.path.exists(fname):
            self._pk , self._sk  = libnacl.crypto_sign_keypair()
            self.dump_keys(fname)
        self.load_keys(fname)

    def _persist_hub(self, addr):
        """
        persist hub connection, connect out
        """
        parts = addr.split(' ')
        host, port = parts[0], int(parts[1])
        con = yield from self._connect_hub(host, port)
        self.persist_hubs[addr] = con
        
    def _persist_hubs(self):
        """
        call every second, keep hub connections persisted
        """
        for addr in self.persist_hubs:
            if self.persist_hubs[addr] is None:
                asyncio.async(self._persist_hub(addr))
        self.loop.call_later(5, self._persist_hubs)
        
    @asyncio.coroutine
    def forward_hub_packet(self, connection, pkt):
        """
        forward URCLINE from connection
        """
        self.log.debug('forward %s' % [pkt])
        for con in self.hubs:
            if con is not connection:
                yield from con.send_hub_packet(pkt)

    def motd(self):
        """
        yield motd 
        """
        yield "This server's public key is %s" % self.get_pubkey()

    @asyncio.coroutine
    def broadcast(self, urcline):
        """
        send urcline to all connection
        """
        if isinstance(urcline, str):
            urcline = urcline.encode('utf-8')
        self.log.info('broadcast {}'.format(urcline))
        pkt = mk_hubpkt(urcline, 1)
        sig = nacl_sign(pkt, self._sk)
        self.log.debug('sig=%s' % [sig])
        return self.forward_hub_packet(None, pkt+sig)

        
    def _new_hub_connection(self, r, w):
        """
        called when we got a new hub connection
        """
        con = urc_hub_connection(self, r, w)
        self.hubs.append(con)
        asyncio.async(self._handle_hub_packet(con))
        return con

    @asyncio.coroutine
    def _connect_hub(self, host, port):
        """
        connect out to a hub
        """
        self.log.info('connecting to hub at {} port {}'.format(host, port))
        r, w = yield from asyncio.open_connection(host, port)
        self.log.info('connected to hub at {} port {}'.format(host, port))
        return self._new_hub_connection(r, w)
 
    def _disconnected(self, con):
        self.log.warn('disconnceted')
        if con in self.hubs:
            self.hubs.remove(con)
            for addr in self.persist_hubs:
                if self.persist_hubs[addr] == con:
                    self.persist_hubs[addr] = None
        if con in self.irc_cons:
            self.irc_cons.remove(con)

    def connect_hub(self, host, port):
        """
        add urc hub to peristed hub connections
        """
        self.log.info('connect to hub at {} port {}'.format(host, port))
        self.persist_hubs['{} {}'.format(host,port)] = None

    def _incoming_hub(self, r, w):
        """
        incoming hub connection
        """
        self.log.info('incoming hub connection')
        self._new_hub_connection(r, w)

    def _incoming_irc(self, r, w):
        """
        incoming irc connection
        """
        self.log.info('incoming irc connection')
        con = irc_handler(self, r, w)
        self.irc_cons.append(con)

    def bind_ircd(self, host, port):
        """
        bind ircd to host:port
        """
        asyncio.async(asyncio.start_server(self._incoming_irc, host, port))
        self.log.info('bind ircd to {} port {}'.format(host,port))

    def bind_hub(self, host, port):
        """
        bind server to host:port
        """
        asyncio.async(asyncio.start_server(self._incoming_hub, host, port))
        self.log.info('bind hub to {} port {}'.format(host,port))


    def _urc_activity(self, nick, chan):
        """
        record urc activity for cache
        """
        tstamp = taia96n_now()
        self.irc_chans[chan][nick] = tstamp
        
    

    def _handle_irc_state(self, src, cmd, dst):
        """
        handle irc server state management
        """
        self.log.debug((src, cmd, dst))
        cmd = cmd.upper()
        chan = irc_parse_channel_name(dst)
        nick, user, serv = irc_parse_nick_user_serv(src) or None, None, None
        if cmd == 'QUIT' and nick:
            for chan in self.irc_chans:
                chan = self.irc_chans[chan]
                if nick in chan:
                    chan.pop(nick)
                    
        if chan and nick:
            # for LIST
            if chan not in self.irc_chans:
                self.irc_chans[chan] = dict()
            # JOIN
            if cmd == 'JOIN' and nick not in self.irc_chans[chan]:
                self._urc_activity(nick, chan)
            # PART
            if cmd == 'PART' and nick in self.irc_chans[chan]:
                self.irc_chan[chan].pop(nick)
            # PRIVMSG from existing
            if cmd == 'PRIVMSG' and nick not in self.irc_chans[chans]:
                self._urc_activity(nick, chan)

    def get_pubkeys(self, fname='pubkeys.txt'):
        """
        get list of public keys
        """
        yield self.get_pubkey()
        if os.path.exists(fname):
            with open(fname) as f:
                for line in f.read().split('\n'):
                    yield line.strip()

    @asyncio.coroutine
    def _handle_hub_packet(self, con):
        """
        obtain a hub packet
        process it
        """
        self.log.debug('handle packet')
        try:
            raw, data, pkttype = yield from con.get_hub_packet()
        except Exception as e:
            self.log.error(e)
            self._disconnected(con)
            raise e
        else:
            if raw in self._urc_cache:
                self.log.debug('drop duplicate')
            else:
                pubkey = None
                _data = None
                if pkttype == 1:
                    sig = data[0-_SIG_SIZE:]
                    body = raw[:0-_SIG_SIZE]
                    self.log.debug('sig is %s' % [sig])
                    self.log.debug('body is %s' % [body])
                    for key in self.get_pubkeys():
                        self.log.debug('try key {}'.format(key))
                        try:
                            pkey = pubkey2bin(key)
                            nacl_verify(body, sig, pkey)
                            pubkey = key
                            self.log.debug('we are %s' % pubkey)
                            data = data[:0-_SIG_SIZE]
                            break
                        except Exception as e:
                            self.log.debug('not key {} because {}'.format(key, e))
                            continue

                self._urc_cache.add(raw)
                _data = data.decode('utf-8')                 
                parsed = parse_urcline(_data)
                if parsed:
                    src, cmd, dst, msg = parsed
                    if dst is None:
                        dst = msg
                    self._handle_irc_state(src, cmd, dst)
                    for irc in self.irc_cons:
                        self.log.debug(irc.chans)
                        if dst in irc.chans:
                            yield from irc.send_line(_data)
                        else:
                            self.log.error('invalid urcline {}'.format(data))
                    yield from self.forward_hub_packet(con, raw)
                asyncio.async(self._handle_hub_packet(con))



def main():
    logging.basicConfig(level = logging.DEBUG)

    import sys
    if len(sys.argv) == 1:
        print ('usage: {} irchost ircport hubhost hubport [remotehubhost remotehubort]'.format(sys.argv[0]))
    else:
        urcd = URCD()
        try:
            urcd.bind_ircd(sys.argv[1], int(sys.argv[2]))
            urcd.bind_hub(sys.argv[3], int(sys.argv[4]))
            if len(sys.argv) == 7:
                urcd.connect_hub(sys.argv[5], int(sys.argv[6]))
                urcd.loop.run_forever()
        finally:
            urcd.loop.close()


if __name__ == '__main__':
    main()
