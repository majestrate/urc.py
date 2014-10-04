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
from random import randrange, Random, randint
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
_RE_LIST_CMD = '^(LIST)'
_RE_PING_CMD = '^PING (.*)$' 
_RE_PONG_CMD = '^PONG (.*)$' 
_RE_MODE_CMD = '^MODE (%s)?\\s(\\w+)$' % _RE_CHAN
_RE_WHO_CMD = '^WHO (%s)$' % _RE_CHAN
_RE_AWAY_ON_CMD = '^AWAY (.+)$'
_RE_AWAY_OFF_CMD = '^(AWAY) ?$'
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


def irc_is_chan(chan):
    """
    return true if something is a channel name
    """
    for p in _CHAN_PREFIX:
        if chan[0] == p:
            return True
    return False

def _irc_re_parse(regex, line):
    m = re.match(regex, line)
    if m:
        return m.groups()

irc_parse_away_on = lambda line : _irc_re_parse(_RE_AWAY_ON_CMD, line)
irc_parse_away_off = lambda line : _irc_re_parse(_RE_AWAY_OFF_CMD, line)
irc_parse_nick_user_serv = lambda line : _irc_re_parse(_RE_SRC_CMD, line)
irc_parse_channel_name = lambda line : _irc_re_parse(_RE_CHAN, line)
irc_parse_nick = lambda line : _irc_re_parse(_RE_NICK_CMD, line)
irc_parse_user = lambda line : _irc_re_parse(_RE_USER_CMD, line)
irc_parse_privmsg = lambda line : _irc_re_parse(_RE_PRIVMSG_CMD, line)
irc_parse_join = lambda line : _irc_re_parse(_RE_JOIN_CMD, line)
irc_parse_multi_join = lambda line : _irc_re_parse(_RE_JOIN_MULTI_CMD, line)
irc_parse_part = lambda line : _irc_re_parse(_RE_PART_CMD, line)
irc_parse_quit = lambda line : _irc_re_parse(_RE_QUIT_CMD, line)
irc_parse_ping = lambda line : _irc_re_parse(_RE_PING_CMD, line)
irc_parse_pong = lambda line : _irc_re_parse(_RE_PONG_CMD, line)
irc_parse_list = lambda line : _irc_re_parse(_RE_LIST_CMD, line)
irc_parse_mode = lambda line : _irc_re_parse(_RE_MODE_CMD, line)
irc_parse_who = lambda line : _irc_re_parse(_RE_WHO_CMD, line)

def irc_greet(serv, nick, user, motd):
    """
    generate an irc greeting for a new user 
    yield lines to send 
    """
    for num , msg in (
            ('001', ':{}'.format(serv)), 
            ('002', ':{}!{}@{}'.format(nick,user,serv)),
            ('003', ':{}'.format(serv)),
            ('004', '{} 0.0 :+'.format(serv)),
            ('005', 'NETWORK=urc.{} CHANTYPES=#&!+ CASEMAPPING=ascii '.format(serv)+
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
    return struct.pack('!QI', sec, nano)

def taia96n_parse(data):
    """
    parse unnecessarily accurate timestamp
    """
    if len(data) != 12: return None
    return struct.unpack('!QI',data)

def filter_urcline(string, filler=''):
    """
    filter undesirable characters out of urcline string
    """
    for bad in '\r\x00':
        string = string.replace(bad, filler)
    return string

def parse_urcline(line):
    """
    return (source, command, destination, message) tuple from URCLINE or None if invalid syntax
    """
    m = re.match(_RE_URCLINE, line)
    if m:
        return m.groups()

def mk_hubpkt(pktdata, pkttype):
    """
    make urc hub packet
    """
    data = bytes()
    pktlen = len(pktdata)
    if pkttype == 1:
        pktlen += _SIG_SIZE
    data += struct.pack('!H', pktlen) # packet length
    data += taia96n_now() # timestamp
    data += struct.pack('!B', pkttype) # packet type
    data += b'\x00\x00\x00'
    data += rand(8) # 64 bit random
    data += pktdata
    return data

class _log:
    """
    non native logger
    """

    
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

class urc_hub_connection:

    def __init__(self, urcd, r, w):
        self.urcd = urcd
        self.r, self.w = r, w
        self._lock = asyncio.Lock()
        inject_log(self)

    @asyncio.coroutine
    def get_hub_packet(self):
        """
        yield a hub packet tuple , (raw_packet, packet_data, packet_type)
        """
        hdr, pktlen, tsec, tnano, pkttype = yield from self._read_hdr()
        data = yield from self._read_data(pktlen)
        return hdr + data , data, pkttype, (tsec, tnano)

    @asyncio.coroutine
    def _read_hdr(self):
        raw = yield from self.r.readexactly(26)
        pktlen = struct.unpack('!H', raw[:2])[0]
        self.log.debug('read packet len={}'.format(pktlen))
        tsec, tnano = taia96n_parse(raw[2:14])
        self.log.debug('packet time {}'.format(tsec))
        pkttype = struct.unpack('!BB', raw[14:16])[0]
        self.log.debug('pkttype={}'.format(pkttype))
        return raw, pktlen, tsec, tnano, pkttype

    @asyncio.coroutine
    def _read_data(self, pktlen):
        data = yield from self.r.readexactly(pktlen)
        self.log.info('data={}'.format([data]))
        return data

    def close(self):
        self.w.transport.close()

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
            data = yield from self.w.drain()
            self.log.info('drained')
        except Exception as e:
            self.log.error(e)
            self.urcd.disconnected(self)
        except asyncio.streams.IncompleteReadError:
            self.log.error('incomplete')
            self.w.transport.close()
            self.urcd.disconnected(self)

class irc_handler:
    """
    simple ircd ui logic
    """

    def __init__(self, daemon, r, w):
        self.daemon = daemon
        self.loop = daemon.loop
        self.r, self.w = r, w
        self.nick = None
        self.user = None
        self.ponged = False
        self._pong = str(randint(100,1000))
        self.greeted = False
        self.chans = list()
        inject_log(self)
        asyncio.async(self.send_line('PING :{}\n'.format(self._pong)))
        asyncio.async(self._get_line())

    @asyncio.coroutine
    def _get_line(self):
        line = yield from self.r.readline()
        if len(line) != 0:
            try:
                yield from self._handle_line(line)
            except Exception as e:
                self.log.error(e)
                self.daemon.disconnected(self)
                raise e
            else:
                asyncio.async(self._get_line())
   
    def change_nick(self, new_nick):
        if self.daemon.has_nick(new_nick):
            line = ':{} 433 {} :Nickname in use\n'.format(self.daemon.name, self.nick)
            asyncio.async(self.send_line(line))
        else:
            line = ':{}!{}@{} NICK {}\n'.format(self.nick,self.user, self.daemon.name, new_nick)
            asyncio.async(self.send_line(line))
            self.nick = new_nick
            self.daemon.inform_chans_for_user(self, line)

    @asyncio.coroutine
    def send_line(self, line):
        """
        send a single line
        """
        self.w.write(line.encode('utf-8'))
        self.log.debug(' <-- {}'.format(line))
        try:
            return self.w.drain() 
        except:
            self.daemon.disconnected(self)

    @asyncio.coroutine
    def send_lines(self, lines):
        """
        send a single line
        """
        _lines = list()
        for line in lines:
            _lines.append(line.encode('utf-8'))
            self.log.debug(' <-- {}'.format(line))
        self.w.writelines(_lines)
        try:
            return self.w.drain() 
        except:
            self.daemon.disconnected(self)

    def _got_pong(self, pong):
        if pong[0] == ':':
            pong = pong[1:]
        if pong == self._pong:
            self.ponged = True
        

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
        _list = irc_parse_list(line)
        _part = irc_parse_part(line)
        _quit = irc_parse_quit(line)
        _privmsg = irc_parse_privmsg(line)
        _ping = irc_parse_ping(line)        
        _pong = irc_parse_pong(line)
        _mode = irc_parse_mode(line)
        _who = irc_parse_who(line)
        _away_on = irc_parse_away_on(line)
        _away_off = irc_parse_away_off(line)


        if _away_on:
            asyncio.async(self.send_line(':{} 306 {} :RPL_UNAWAY\n'.format(self.daemon.name, self.nick)))
            
        if _away_off:
            asyncio.async(self.send_line(':{} 305 {} :RPL_AWAY\n'.format(self.daemon.name, self.nick)))
            
        if _pong:
            self._got_pong(_pong[0])
        # WHO
        if _who:
            lines = list()
            lines.append(':{} 352 {} {} {} {} {} {} H :0 {}\n'.format(self.daemon.name, self.nick,
                                                                                     _who[0], self.nick, 
                                                                                     self.daemon.name, self.nick, 
                                                                                     self.nick, self.nick))
            lines.append((':{} 315 {} {} :RPL_ENDOFWHO\n'.format(self.daemon.name, self.nick, _who[0])))
            asyncio.async(self.send_lines(lines))
        # MODE
        if _mode:
            asyncio.async(self.send_line(':{} 324 {} {} +n\n'.format(self.daemon.name, self.nick, _mode[0])))
        # LIST
        if _list:
            self.log.info('list')
            lines = list()
            lines.append(':{} 321 {} CHANNELS :USERS TOPIC\n'.format(self.daemon.name, self.nick))
            for c in self.daemon.irc_chans:
                chan = self.daemon.irc_chans[c]
                lines.append(':{} 322 {} {} {} :URCD\n'.format(self.daemon.name, self.nick, c, len(chan)))
            lines.append(':{} 323 {} :RPL_LISTEND\n'.format(self.daemon.name, self.nick))
            asyncio.async(self.send_lines(lines))
        # PING
        if _ping:
            if _ping[0][0] != ':':
                _ping = ':{}'.format( _ping[0] )
            else: 
                _ping = _ping[0]
            asyncio.async(self.send_line(':{} PONG {}\n'.format(self.daemon.name, _ping)))
        # QUIT
        if _quit:
            self.w.write_eof()
            self.w.transport.close()
            self.daemon.disconnected(self)
        # NICK
        if self.nick is None and _nick is not None:
            self.nick = _nick[0]
        elif self.nick is not None and _nick is not None:
            self.change_nick(_nick[0])
            
        # USER
        if self.user is None and _user is not None:
            self.user = _user[0]
        
        if self.greeted and self.ponged:
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
                self.daemon.joined(self, chan)
                self.daemon.activity(self.nick, chan)
                lines = list()
                lines.append(':{}!{}@{} JOIN {}\n'.format(self.nick, self.user, self.daemon.name, chan))
                lines.append(':{} 353 {} = {} :{}\n'.format(self.daemon.name, self.nick, chan, self.nick))
                lines.append(':{} 366 {} {} :RPL_ENDOFNAMES\n'.format(self.daemon.name, self.nick, chan))
                asyncio.async(self.send_lines(lines))
                
            # PART
            if _part and _part in self.chans:
                self.chans.remove(_part)
                line = ':{}!{}@{} PART {}\n'.format(self.nick, self.user, self.daemon.name, chan)
                asyncio.async(self.send_line(line))
            
            # PRVIMSG
            if _privmsg:
                dest, msg = _privmsg
                self.daemon.activity(self.nick, dest)
                line = ':{}!{}@{} PRIVMSG {} :{}\n'.format(self.nick, self.user, 
                                                           self.daemon.name, dest, msg)
                if irc_is_chan(dest):
                    self.daemon.inform_chans_for_user(self, line)
                else:
                    if dest == '*urcd' and False: # todo: implement
                        self.daemon.handle_control(self, msg)
                    else:
                        for con in self.daemon.irc_cons:
                            if con.nick == dest:
                                asyncio.async(con.send_line(line))
                                return
                self.daemon.broadcast(line)
        else:
            if self.nick is not None and self.user is not None:
                self.greeted = True
                asyncio.async(self.send_lines(irc_greet(self.daemon.name, self.nick, self.user, self.daemon.motd())))




class IRCD:
    """
    simple ircd UI
    """

    def __init__(self, urcd):
        self.name = 'irc.%s.tld' % urcd.get_pubkey()[:8]
        self.irc_cons = list()
        self.irc_chans = dict()
        self.urcd = urcd
        self.loop = asyncio.get_event_loop()
        inject_log(self)

    def handle_control(self, con, msg):
        if self.auth.connection_authed(con):
            asyncio.async(self.controller.handle(con, msg))
        else:
            asyncio.async(self.auth.handle(con, msg))

    def joined(self, con, chan):
        """
        a user has joined a channel
        """
        line = ':{}!{}@{} JOIN :{}\n'.format(con.nick, con.user, self.name, chan)
        for user in self.irc_cons:
            if chan in user.chans:
                asyncio.async(user.send_line(line))
            

    def has_nick(self, nick):
        """
        return True if this ircd has a user with nickname nick connected
        """
        for user in self.irc_cons:
            if user.nick == nick:
                return True
        return False

    def motd(self, fname='motd.txt'):
        """
        read motd file
        """
        if os.path.exists(fname):
            with open(fname) as f:
                for line in f.read().split('\n'):
                    yield line
        yield "this server's public key is {}".format(self.urcd.get_pubkey())
    

    def incoming_connection(self, r, w):
        """
        handle incoming connections
        """
        con = irc_handler(self, r, w)
        self.irc_cons.append(con)

    def inform_chans_for_user(self, user, line):
        """
        send a line to every user that is in every channel this user is in
        """
        self.log.debug('inform chans for {} : {}'.format(user.nick, [line]))
        for con in self.irc_cons:
            if con == user:
                continue
            for chan in user.chans:
                if chan in con.chans:
                    asyncio.async(con.send_line(line))
                    break

    def user_quit(self, con):
        """
        tell appropriate users that a user quit
        """   

        line = ':{}!{}@{} QUIT :quit\n'.format(con.nick, con.user, self.name)
        self.urcd.broadcast(line)
        # find all users in every chan they are in
        # give them a quit message from this user
        users = list()
        for chan in con.chans:
            # remove connection from channel
            _chan = self.irc_chans[chan]
            if con.nick in _chan:
                _chan.pop(con.nick)
        # inform users of quit
        self.inform_chans_for_user(con, line)


    def disconnected(self, con):
        """
        handle connection lost
        """
        self.irc_cons.remove(con)
        self.user_quit(con)

    def activity(self, nick, chan):
        """
        called when we got activity by user with nick in channel chan
        """
        tstamp = taia96n_now()
        if chan not in self.irc_chans:
            self.irc_chans[chan] = dict()
        self.irc_chans[chan][nick] = tstamp

    def urc_activity(self, src, cmd, dst, msg):
        """
        update the state of the ircd from a remote line
        """
        if msg is None:
            line = ':{} {} {}\n'.format(src, cmd, dst)
        elif dst is None:
            line = ':{} {} :{}\n'.format(src, cmd, msg)
        else:
            line = ':{} {} {} :{}\n'.format(src, cmd, dst, msg)

        self.log.debug((src, cmd, dst, msg))
        cmd = cmd.upper()
        if dst is None:
            _chan = irc_is_chan(msg) and msg or None
        else:
            _chan = irc_is_chan(dst) and dst or None

        _nick = None

        if _chan is None:
            _nick = dst
        self.log.debug((_chan, _nick, line))

        nick, user, serv = irc_parse_nick_user_serv(src) or None, None, None

        if _chan and _nick:
            # for LIST
            if _chan not in self.irc_chans:
                self.irc_chans[_chan] = dict()
            # JOIN
            if cmd == 'JOIN' and _nick not in self.irc_chans[_chan]:
                self.activity(_nick, _chan)
            # PRIVMSG 
            if cmd == 'PRIVMSG' and _nick:
                self.activity(_nick, _chan)
        

       
        if _nick:
            for user in self.irc_cons:
                if user.nick == _nick: 
                    asyncio.async(user.send_line(line))
                    return
        
        for irc in self.irc_cons:
            self.log.debug(irc.chans)
            if _chan in irc.chans:
                asyncio.async(irc.send_line(line))
            

    def broadcast(self, line):
        """
        broadcast a line to the network
        """
        self.urcd.broadcast(line)
 
class URCD:
    """
    urcd server context
    """

    def __init__(self, sign=True):
        self.initkeys()
        self.sign = sign
        print ('sign=%s'%sign)
        self.ircd = IRCD(self)
        self.hubs = list()
        self.persist_hubs = dict()
        self.hooks = list()
        self.loop = asyncio.get_event_loop()
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


    def broadcast(self, urcline):
        """
        send urcline to all connection
        """
        if isinstance(urcline, str):
            urcline = urcline.encode('utf-8')
        self.log.info('broadcast {}'.format(urcline))
        if self.sign:
            pkt = mk_hubpkt(urcline, 1)
            sig = nacl_sign(pkt, self._sk)
            self.log.debug('sig=%s' % [sig])
            pktdata = pkt + sig
        else:
            pktdata = mk_hubpkt(urcline, 0)
        self._urc_cache.add(pktdata)
        asyncio.async(self.forward_hub_packet(None, pktdata))

        
    def _new_hub_connection(self, r, w):
        """
        called when we got a new hub connection
        """
        con = urc_hub_connection(self, r, w)
        self.hubs.append(con)
        asyncio.async(self._get_hub_packet(con))
        return con

    @asyncio.coroutine
    def _connect_hub(self, host, port):
        """
        connect out to a hub
        """
        self.log.info('connecting to hub at {} port {}'.format(host, port))
        r, w = yield from asyncio.open_connection(host, port)
        #r, w = yield from asyncio.open_connection('127.0.0.1', 9050)
        #self.log.info('connection to tor made')
        #w.write(b'\x05\x01\x00')
        #data = yield from w.drain()
        
        self.log.info('connected to hub at {} port {}'.format(host, port))
        
        return self._new_hub_connection(r, w)
 
    def disconnected(self, con):
        """
        urc hub has disconnected
        """
        self.log.info('hub disconnceted')
        if con in self.hubs:
            self.hubs.remove(con)
            for addr in self.persist_hubs:
                if self.persist_hubs[addr] == con:
                    self.persist_hubs[addr] = None

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

    def bind_ircd(self, host, port):
        """
        bind ircd to host:port
        """
        asyncio.async(asyncio.start_server(self.ircd.incoming_connection, host, port))
        self.log.info('bind ircd to {} port {}'.format(host,port))

    def bind_hub(self, host, port):
        """
        bind server to host:port
        """
        asyncio.async(asyncio.start_server(self._incoming_hub, host, port))
        self.log.info('bind hub to {} port {}'.format(host,port))        
    


    def get_pubkeys(self, fname='pubkeys.txt'):
        """
        get list of public keys
        """
        yield self.get_pubkey()
        if os.path.exists(fname):
            with open(fname) as f:
                for line in f.read().split('\n'):
                    yield line.strip()

    def _get_hub_packet(self, con):
        """
        obtain a hub packet
        """
        try:
            self.log.debug('get packet')
            raw, data, pkttype, tstamp  = yield from con.get_hub_packet()
        except asyncio.streams.IncompleteReadError:
            con.close()
            self.disconnected(con)
        except Exception as e:
            self.log.error(e)
            self.disconnected(con)
            raise e
        else:
            asyncio.async(self._handle_hub_packet(con, raw, data, pkttype, tstamp))

    def _bad_timestamp(self, tstamp, dlt=15):
        """
        return true if timestamp is too old or too new
        """
        nowsec, nownano = taia96n()
        thensec, thennano = tstamp
        return abs(nowsec - thensec) > dlt

    @asyncio.coroutine
    def _handle_hub_packet(self, con, raw, data, pkttype, tstamp):
        """
        process hub packet
        """
        self.log.debug('handle packet')
        if self._bad_timestamp(tstamp):
            self.log.info('bad timestamp')
        elif raw not in self._urc_cache:
            pubkey = None
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
            if pubkey is not None or pkttype == 0:
                _data = data.decode('utf-8')                 
                parsed = parse_urcline(_data)
                if parsed:
                    src, cmd, dst, msg = parsed
                    self.ircd.urc_activity(src, cmd, dst, msg)
            asyncio.async(self.forward_hub_packet(con, raw))
        asyncio.async(self._get_hub_packet(con))


def get_log_lvl(lvl):
    """
    get logging level via string
    """
    lvl = lvl.lower()
    if lvl == 'debug':
        return logging.DEBUG
    if lvl == 'info':
        return logging.INFO
    if lvl == 'warn':
        return logging.WARN
    if lvl == 'error':
        return logging.ERROR

def main():
    import argparse
    ap = argparse.ArgumentParser()

    ap.add_argument('--log', type=str, default='warn')
    ap.add_argument('--irc', type=str, default='::1')
    ap.add_argument('--irc-port', type=int, default=6667)
    ap.add_argument('--remote-hub', type=str, required=True)
    ap.add_argument('--remote-hub-port', type=int, default=6666)
    ap.add_argument('--hub', type=str, default=None)
    ap.add_argument('--hub-port', type=int, default=6666)
    ap.add_argument('--sign',type=str, default='no')
    
    args = ap.parse_args()

    loglvl = get_log_lvl(args.log)

    logging.basicConfig(level = loglvl, format='%(asctime)s [%(levelname)s] %(name)s : %(message)s')
    import sys
    if len(sys.argv) == 1:
        print ('usage: {} irchost ircport remotehubhost remotehubort [hubhost hubort]'.format(sys.argv[0]))
    else:
        urcd = URCD(sign=args.sign.lower() == 'yes')
        try:
            urcd.bind_ircd(args.irc, args.irc_port)
            urcd.connect_hub(args.remote_hub, args.remote_hub_port)
            if args.hub:
                urcd.bind_hub(args.hub, args.hub_port)
            urcd.loop.run_forever()
        finally:
            urcd.loop.close()


if __name__ == '__main__':
    main()
