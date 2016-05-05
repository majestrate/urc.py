#!/usr/bin/env python3
# 
# urc.py -- one long long horrible python script
#
# monolithic urc hub in python
#
# public domain
#


# for hexchat
__module_name__ = "urc"
__module_version__ = "0.1"
__module_description__ = "urc network plugin"

import binascii
import struct
import asyncio
from random import randrange, Random, randint
import random
import string
import socket
import time
import logging
import os
import threading
from hashlib import sha256

try:
    import hexchat
except ImportError:
    hexchat = None

def prnt(*args):
    if hexchat:
        s = ''
        for arg in args:
            s += '{}'.format(arg)
        hexchat.prnt(s)
    else:
        print (args)
    
# for urc_sign
try:
    prnt("trying to load libnacl")
    import libnacl
except ImportError:
    prnt("no libnacl, will not do signed messages")
    libnacl = None
else:
    prnt("libnacl loaded")

# -- urc message types
URC_PLAIN = struct.unpack('!H', b'\x00\x00')[0]
URC_SIGN = struct.unpack('!H', b'\x01\x00')[0]
URC_PY_SIGN = struct.unpack('!H', b'\x01\x01')[0]


# -- not cryptographically secure random for non encryption uses
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
_RE_NICK_CMD = '^NICK :?(%s)' % _RE_NICK
_RE_USER_CMD = '^USER (%s) [%s\\*]+ [%s\\*]+\s:?%s' % ( _RE_NICK, _RE_CHARS, _RE_CHARS, _RE_NICK )
_RE_PRIVMSG_CMD = '^PRIVMSG (%s|%s) :?(.+)$' % (_RE_NICK, _RE_CHAN)
_RE_JOIN_CMD = '^JOIN (%s)' % _RE_CHAN
_RE_JOIN_MULTI_CMD = '^JOIN :?(.+)' 
_RE_PART_CMD = '^PART (%s) :?(.+)$' % _RE_CHAN
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

_SIG_SIZE = libnacl and libnacl.crypto_sign_BYTES or 0

def nacl_keygen(seed=None):
    """
    generate nacl keypair
    """
    if not seed:
        seed = libnacl.randombytes(libnacl.crypto_sign_SEEDBYTES)
    sk, vk = libnacl.crypto_sign_seed_keypair(seed)
    return sk, vk, seed

def nacl_verify(m, s, pk):
    """
    verify message m with signature s for public key pk
    """
    if libnacl:
        libnacl.crypto_sign_open(s+m, pk)

def nacl_sign(m, sk):
    """
    sign message m with secret key sk
    return signed message
    """
    if libnacl:
        s = libnacl.crypto_sign(m,sk)[:_SIG_SIZE]
        assert len(s) == _SIG_SIZE
        return s 

def pubkey2bin(pk):
    return binascii.unhexlify(pk)

def bin2pubkey(bin):
    return binascii.hexlify(bin).decode('ascii')

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

def mk_hubpkt(pktdata, pkttype=URC_PLAIN):
    """
    make urc hub packet
    """
    data = bytes()
    pktlen = len(pktdata)
    if pkttype == URC_PY_SIGN:
        pktlen += _SIG_SIZE
    data += struct.pack('!H', pktlen) # packet length
    data += taia96n_now() # timestamp
    data += struct.pack('!H', pkttype) # packet type
    data += b'\x00\x00'
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
        prnt ('<urc.py> '+''.join(args))

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
        inject_log(self)

    @asyncio.coroutine
    def get_hub_packet(self):
        """
        yield a hub packet tuple , (raw_packet, packet_data, packet_type)
        """
        pkt = yield from self._read_hdr()
        if pkt:
            hdr, pktlen, tsec, tnano, pkttype = pkt
            data = yield from self._read_data(pktlen)
            return hdr + data , data, pkttype, (tsec, tnano)

    @asyncio.coroutine
    def _read_hdr(self):
        try:
            raw = yield from self.r.readexactly(26)
        except:
            self.close()
            self.urcd.disconnected(self)
        else:
            pktlen = struct.unpack('!H', raw[:2])[0]
            self.log.debug('read packet len={}'.format(pktlen))
            tsec, tnano = taia96n_parse(raw[2:14])
            self.log.debug('packet time {}'.format(tsec))
            pkttype = struct.unpack('!H', raw[14:16])[0]
            self.log.debug('pkttype={}'.format(pkttype))
            return raw, pktlen, tsec, tnano, pkttype


    @asyncio.coroutine
    def _read_data(self, pktlen):
        data = yield from self.r.readexactly(pktlen)
        self.log.debug('data={}'.format([data]))
        return data

    def close(self):
        self.w.transport.close()

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
        self._last_ping = time.time()
        self._pings = dict()
        inject_log(self)
        asyncio.async(self.send_line('PING :{}\n'.format(self._pong)))
        asyncio.async(self._get_line())

    def disconnect(self):
        """
        disconnect this user
        """
        self.log.info('disconnect user')
        self.w.close()
        self.w = None
        self.r = None

    def ping(self):
        """
        ping this user
        """
        ping = int(time.time())
        self._pings[str(ping)] = ping
        asyncio.async(self.send_line('PING :{}\n'.format(ping)))
        
    @asyncio.coroutine
    def _get_line(self):
        if self.r is None:
            return
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
        if self.daemon.anon or self.daemon.has_nick(new_nick):
            line = ':{} 433 {} :{}\n'.format(self.daemon.name, self.nick, new_nick)
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
        if self.w is None:
            return
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


    def _ack_ping(self, ping):
        """
        ack a ping that may or may not have been sent
        """
        if ping in self._pings:
            self._pings.pop(ping)
            self._last_ping = time.time()

    def is_timed_out(self):
        """
        has this connection timed out?
        """
        return ( time.time() - self._last_ping ) > self.daemon.ping_timeout
            
    @asyncio.coroutine
    def _handle_line(self, line):
        """
        handle a line from irc client
        """
        line = line.decode('utf-8')
        line = filter_urcline(line)
        line = line.replace("\r\n", "\n")
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
                if irc_is_chan(c) and len(chan) > 0:
                    lines.append(':{} 322 {} {} {} :{}\n'.format(self.daemon.name, self.nick, c, 9000 + randint(10, 100), "URC RELAY CHAT"))
            lines.append(':{} 323 {} :RPL_LISTEND\n'.format(self.daemon.name, self.nick))
            asyncio.async(self.send_lines(lines))
        # PING
        if _ping:
            if _ping[0][0] != ':':
                _ping = ':{}'.format( _ping[0] )
            else: 
                _ping = _ping[0]
            asyncio.async(self.send_line(':{} PONG {}\n'.format(self.daemon.name, _ping)))
        # PONG
        if _pong:
            if _pong[0][0] == ':':
                self._ack_ping(_pong[0][1:])
            else:
                self._ack_ping(_pong[0])
                
        # QUIT
        if _quit:
            self.w.write_eof()
            self.w.transport.close()
            self.daemon.disconnected(self)
        # NICK
        if self.nick is None and _nick is not None:
            if self.daemon.anon:
                self.nick = 'anon'
            else:
                _nick = self.daemon.filter_nick(_nick[0])
                self.nick = _nick
        elif self.nick is not None and _nick is not None:
            _nick = self.daemon.filter_nick(_nick[0])
            self.change_nick(_nick)
            
        # USER
        if self.user is None and _user is not None:
            if self.daemon.anon:
                self.user = 'anon'
            else:
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
                chan = chan.strip()
                self.log.debug('join {}'.format(chan))
                if chan in self.chans:
                    self.log.debug('not joining {}'.format(chan))
                    continue
                self.chans.append(chan)
                self.daemon.joined(self, chan)
                self.daemon.activity(self.nick, chan)
                lines = list()
                for user in self.daemon.irc_cons:
                    if chan in user.chans:
                        lines.append(':{} 353 {} = {} :{}\n'.format(self.daemon.name, self.nick, chan, user.nick))
                if chan in self.daemon.irc_chans[chan]:
                    for user in self.daemon.irc_chans[chan]:
                        match = irc_parse_nick_user_serv(user)
                        if match:
                            nick = match[0]
                            lines.append(':{} 353 {} = {} :{}\n'.format(self.daemon.name, self.nick, chan, nick))

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

    def __init__(self, urcd, controller, check_auth, do_auth):
        self.name = 'irc.%s.tld' % urcd.name
        self.anon = True
        self.irc_cons = list()
        self.irc_chans = dict()
        self.urcd = urcd
        self.controller_hook = controller
        self.do_auth_hook = do_auth
        self.check_auth_hook = check_auth
        self.loop = asyncio.get_event_loop()
        self.ping_interval = 60
        self.ping_tries = 3
        self.ping_timeout = self.ping_interval * self.ping_tries
        inject_log(self)
        self.loop.call_later(1, self.send_pings)
        self.loop.call_later(1, self.check_ping_timeout)

    def send_pings(self):
        """
        send pings
        """
        for con in self.irc_cons:
            con.ping()
        self.loop.call_later(self.ping_interval, self.send_pings)


    def check_ping_timeout(self):
        """
        check for ping timeouts
        remove as needed
        """
        for con in self.irc_cons:
            if con.is_timed_out():
                con.disconnect()
                self.disconnected(con)
        self.loop.call_later(5, self.check_ping_timeout)
            
    def filter_nick(self, nick):
        """
        do nickname rewrite rules
        """
        if nick == 'nameless':
            nick = self.randnick()
            while self.has_nick(nick):
                nick = self.randnick()
        return nick

    def randnick(self, nicklen=7, vowels='aeiou', letters='cvbnmlkhgfdswrtp', numbers='1234567890'):
        """
        generate random nickname
        """
        ret = str()
        for n in range(nicklen):
            chars = letters
            if n % 2 != 0:
                chars = vowels
            ret += random.choice(chars).lower()
        return ret

    def handle_control(self, con, msg):
        """
        handle admin actions
        """
        if self.check_auth_hook(con):
            asyncio.async(self.controller_hook(con, msg))
        else:
            asyncio.async(self.do_auth_hook(con, msg))

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
        yield 'our public key is {}'.format(self.urcd.pubkey())
        if os.path.exists(fname):
            with open(fname) as f:
                for line in f.read().split('\n'):
                    yield line
        else:
            yield 'Channels are empty at first'

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

        # find all users in every chan they are in
        # give them a quit message from this user
        users = list()
        for chan in con.chans:
            # remove connection from channel
            _chan = self.irc_chans[chan]
            if con.nick in _chan:
                _chan.pop(con.nick)


    def disconnected(self, con):
        """
        handle connection lost
        """
        self.log.info('disconnecting {}'.format(con))
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
        if _chan:
            for irc in self.irc_cons:
                self.log.debug(irc.chans)
                if _chan in irc.chans:
                    asyncio.async(irc.send_line(line))
            

    def broadcast(self, line):
        """
        broadcast a line to the network
        """
        self.urcd.broadcast(line)


class AdminUI:
    """
    urc.py irc admin interface
    """

    def __init__(self, urcd):
        self.urcd = urcd

    @asyncio.coroutine
    def handle_admin(self, con, msg):
        """
        handle an admin action
        """

    def check_auth(self, con):
        """
        check if a connection is authenticated with the admin ui
        """

    @asyncio.coroutine
    def handle_auth(self, con, msg):
        """
        handle login attempt from connection
        """

class URCD:
    """
    urcd server context
    """

    def __init__(self, sign=True, name='urc.py', irc=True, loop=None):
        inject_log(self)
        self.sign = sign
        if sign:
            self.loadkey()
            self.log.info('our pubkey is {}'.format(self.pubkey()))
        else:
            self.pk = None
            self.sk = None
        self.name = name
        if irc:
            self.admin = AdminUI(self)
            self.ircd = IRCD(self, self.admin.handle_admin, self.admin.check_auth, self.admin.handle_auth)
        else:
            self.admin = None
            self.ircd = None
        if loop is not None:
            self.loop = loop
        else:
            self.loop = asyncio.get_event_loop()
        self.gui = None
        self.hubs = list()
        self.persist_hubs = dict()
        self.hooks = list()
        self._urc_cache = _bloom_filter(32 * 1024, 4)

    def start(self):
        self.loop.call_later(1, self._persist_hubs)

    def loadkey(self, keyfile='privkey.dat'):
        if os.path.exists(keyfile):
            with open(keyfile, 'rb') as rf:
                seed = rf.read()
            self.sk, self.pk, seed = nacl_keygen(seed)
        else:
            self.sk, self.pk, seed = nacl_keygen()
            with open(keyfile, 'wb') as wf:
                wf.write(seed)
        
    def _persist_hub(self, addr):
        """
        persist hub connection, connect out
        """
        parts = addr.split(' ')
        host, port = parts[0], int(parts[1])
        con = yield from self._connect_hub(host, port)
        if con is None:
            self.persist_hubs[addr] = None
            return
        self.persist_hubs[addr] = con


    def pubkey(self):
        """
        get ascii representation of our public key
        """
        return self.pk and bin2pubkey(self.pk) or 'not made'
        
    def _persist_hubs(self):
        """
        call every second, keep hub connections persisted
        """
        for addr in self.persist_hubs:
            if self.persist_hubs[addr] is None:
                asyncio.async(self._persist_hub(addr), loop=self.loop)
        self.loop.call_later(1, self._persist_hubs)
        
    @asyncio.coroutine
    def forward_hub_packet(self, connection, pkt, min_delay=1, max_delay=3):
        """
        forward URCLINE from connection
        """
        sleeptime = random.randint(100, 1000)
        self.log.info("sleep {}ms".format(sleeptime))
        _ = yield from asyncio.sleep(float(sleeptime) / 1000.0, loop=self.loop)
        for k in self.persist_hubs:
            con = self.persist_hubs[k]
            if con is not 0 and con is not None:
                if con != connection:
                    asyncio.async(con.send_hub_packet(pkt), loop=self.loop)
        for con in self.hubs:
            if con != connection:
                asyncio.async(con.send_hub_packet(pkt), loop=self.loop)

    def broadcast(self, urcline):
        """
        send urcline to all connection
        """
        if isinstance(urcline, str):
            urcline = urcline.encode('utf-8')
        self.log.info('broadcast {}'.format(urcline))
        msgtype = URC_PLAIN
        sig = bytearray()
        if self.sign:
            msgtype = URC_PY_SIGN
            sig = nacl_sign(self.sk, urcline)
        pktdata = mk_hubpkt(urcline, msgtype) + sig
        self._urc_cache.add(pktdata)
        asyncio.async(self.forward_hub_packet(None, pktdata), loop=self.loop)

        
    def _new_hub_connection(self, r, w):
        """
        called when we got a new hub connection
        """
        con = urc_hub_connection(self, r, w)
        asyncio.async(self._get_hub_packet(con), loop=self.loop)
        return con

    def _socks_handshake(self, r, w, host, port):
        """
        do socks v5 handshake
        """

        w.write(b'\x05\x01\x00')
        _ = yield from w.drain()
        data = yield from r.readexactly(2)
        self.log.debug('read handshake %r' % data)
        req = struct.pack('!BBBBB', 5, 1, 0,  3, len(host))
        req += host.encode('utf-8')
        req += struct.pack('!H', port)
        self.log.debug('write request %r' % req)
        w.write(req)
        _ = yield from w.drain()
        self.log.debug('read response %d bytes' % len(req))
        data = yield from r.readexactly(4)
        if data[3] == 1:
            _ = yield from r.readexactly(4)
        else:
            self.log.debug('wtf?')
            w.close()
        port = yield from r.readexactly(2)
        self.log.debug(struct.unpack('!H', port))
        return data[1] == 0
        
    
    def _connect_hub(self, host, port):
        """
        connect out to a hub
        """
        hub = '{} {}'.format(host, port)
        self.persist_hubs[hub] = 0

        prnt('connecting to hub at {} port {}'.format(host, port))
        if hasattr(self, 'use_socks') and self.use_socks:
            r, w = yield from asyncio.open_connection(self.socks_host, int(self.socks_port), loop=self.loop)
            result = yield from self._socks_handshake(r, w, host, int(port))
            self.log.debug('socks = {}'.format(result))
        else:
            try:
                r, w = yield from asyncio.open_connection(host, int(port), loop=self.loop)
            except Exception as e:
                prnt('error connecting to {} {} {}'.format(host, port, e))
                return
            else:
                result = True
        if result is True:
            prnt('connected to hub at {} port {}'.format(host, port))
            con = self._new_hub_connection(r, w)
            con.addr = hub
            return con
        else:
            prnt('connection to hub at {} port {} failed'.format(host, port))
            w.close()
 
    def disconnected(self, con):
        """
        urc hub has disconnected
        """
        prnt ('hub connection to {} lost'.format(con.addr))
        self.log.info('hub disconnceted')
        if con.addr in self.persist_hubs:
            self.persist_hubs[con.addr] = None
        if con in self.hubs:
            self.hubs.remove(con)
        

    def connect_hub(self, host, port):
        """
        add urc hub to peristed hub connections
        """
        self.log.info('connect to hub at {} port {}'.format(host, port))
        self.persist_hubs['{} {}'.format(host,port)] = None

    def disconnect(self):
        self.loop.call_soon(self._disconnnect_all)

    def _disconnnect_all(self):
        hub_keys = list(self.persist_hubs.keys())
        for key in hub_keys:
            self._remove_hub(key)
        
    def disconnect_hub(self, host, port):
        self.loop.call_soon(self._remove_hub, "{} {}".format(host, port))

    def _remove_hub(self, name):
        if name in self.persist_hubs:
            hub = self.persist_hubs[name]
            if hub:
                hub.close()
            del self.persist_hubs[name]
            prnt("disconnected from {}".format(name))
        
    def _incoming_hub(self, r, w):
        """
        incoming hub connection
        """
        self.log.info('incoming hub connection')
        con = self._new_hub_connection(r, w)
        con.addr = None
        self.hubs.append(con)

    def bind_ircd(self, host, port):
        """
        bind ircd to host:port
        """
        if self.ircd:
            asyncio.async(asyncio.start_server(self.ircd.incoming_connection, host, port), loop=self.loop)
            self.log.info('bind ircd to {} port {}'.format(host,port))

    def bind_hub(self, host, port):
        """
        bind server to host:port
        """
        asyncio.async(asyncio.start_server(self._incoming_hub, host, port), loop=self.loop)
        self.log.info('bind hub to {} port {}'.format(host,port))        
    


    def get_pubkeys(self, fname='pubkeys.txt'):
        """
        get list of public keys
        """
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
            
            pkt = yield from con.get_hub_packet()
            if pkt:
                raw, data, pkttype, tstamp = pkt
            else:
                return
        except:
            con.close()
            self.disconnected(con)
            raise
        else:
            asyncio.async(self._handle_hub_packet(con, raw, data, pkttype, tstamp), loop=self.loop)

    def _bad_timestamp(self, tstamp, dlt=128):
        """
        return true if timestamp is too old or too new
        """
        nowsec, nownano = taia96n()
        thensec, thennano = tstamp
        if abs(nowsec - thensec) > dlt:
            self.log.debug(nowsec - thensec)
            return True
        return False

    def set_proxy(self, host, port):
        """
        set socks proxy
        """
        self.socks_host = host
        self.socks_port = port
        self.use_socks = True
    
    def urc_activity(self, src, cmd, dst, msg):
        """
        called when we got a message from urc
        """
        if self.ircd:
            self.ircd.urc_activity(src, cmd, dst, msg)
        if self.gui:
            if dst and dst[0] in ['#', '&', '+', '$']:
                ctx = self.gui.find_context(channel=dst)
                if ctx:
                    ev = "Channel Message"
                    if cmd != "PRIVMSG":
                        ctx.prnt(":{} {} {} :{}".format(src, cmd, dst, msg))
                    else:
                        src = src.split("!")[0]
                        ctx.emit_print(ev, "<<{}>>".format(src), msg, "")
    
    @asyncio.coroutine
    def _handle_hub_packet(self, con, raw, data, pkttype, tstamp):
        """
        process hub packet
        """
        self.log.debug('handle packet')
        if self._bad_timestamp(tstamp):
            self.log.info('bad timestamp')
        elif raw not in self._urc_cache:
            self._urc_cache.add(raw)
            pubkey = None
            if pkttype == URC_SIGN:
                sig = raw[0-_SIG_SIZE:]
                body = data
                self.log.debug('urcsign sig={}, body={}'.format(sig, body))
            if pkttype == URC_PY_SIGN:
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
                        

            if pkttype == URC_PY_SIGN and pubkey is None:
                data = data[:0-_SIG_SIZE]
            try:
                _data = data.decode('utf-8')
            except UnicodeDecodeError:
                pass
            else:
                parsed = parse_urcline(_data)
                if parsed:
                    src, cmd, dst, msg = parsed
                    if pubkey == None and pkttype == URC_PY_SIGN:
                        src = 'fakeuser!lamer@spoof'
                    self.urc_activity(src, cmd, dst, msg)
            asyncio.async(self.forward_hub_packet(con, raw), loop=self.loop)
        asyncio.async(self._get_hub_packet(con), loop=self.loop)



        

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

def urc_broadcast_hexchat(word, word_eol, userdata):
    chnl = hexchat.get_info("channel")
    if chnl:
        nick = hexchat.get_info("nick")
        if nick is None or len(nick) == 0:
            nick = "anon"
        try:
            userdata.broadcast(':{}!hexchat@urc.py.tld PRIVMSG {} :{}\n'.format(nick, chnl, word_eol[0]))
        except Exception as e:
            prnt("error in urc: {}".format(e))
            

def urc_command_hexchat(word, word_eol, userdata):
    if len(word) < 2:
        prnt("invalid use of urc command")
        return hexchat.EAT_ALL
    cmd = word[1]
    if cmd == "proxy":
        if len(word) > 2:
            host = word[2]
        if len(word) > 3:
            try:
                port = int(word[3])
            except ValueError:
                prnt("invalid proxy port: {}".format(word[3]))
                return hexchat.EAT_ALL
        prnt("set proxy to {}:{}".format(host, port))
        userdata.set_proxy(host, port)
    if cmd == "connect":
        host = ""
        port = 6789
        if len(word) > 2:
            host = word[2]
        if len(word) > 3:
            try:
                port = int(word[3])
            except ValueError:
                prnt("invalid port: {}".format(word[3]))
                return hexchat.EAT_ALL
        if len(host) > 0:
            userdata.connect_hub(host, port)
        else:
            prnt("cannot connect, no hub specificed")
        return hexchat.EAT_ALL
    elif cmd == "msg":
        urc_broadcast_hexchat(word[1:], word_eol[1:], userdata)
        return hexchat.EAT_ALL
    elif cmd == "disconnect":
        if len(word) == 2:
            userdata.disconnect()
        elif len(word) > 2:
            host = word[2]
            port = 6789
            if len(word) > 3:
                try:
                    port = int(word[3])
                except ValueError:
                    prnt("invalid port: {}".format(word[3]))
                    return hexchat.EAT_ALL
            userdata.disconnect_hub(host, port)
        return hexchat.EAT_ALL
        
def urc_unload_hexchat(userdata):
    try:
        userdata.loop.close()
    except Exception as e:
        prnt("error unloading urc: {}".format(e))
        
if hexchat:
    urcd = URCD(False, 'hexchat', False, False)
    urcd.gui = hexchat
    urcd.set_proxy("127.0.0.1", 9150)
    hexchat.hook_command('', urc_broadcast_hexchat, urcd)
    hexchat.hook_command('urc', urc_command_hexchat, urcd)
    hexchat.hook_unload(urc_unload_hexchat, urcd)
    def runhub(urc):
        prnt("starting up URC HUB")
        urc.loop = asyncio.new_event_loop()
        try:
            urc.start()
            urc.loop.run_forever()
        except Exception as e:
            prnt("error in urc mainloop: {}".format(e))
    threading.Thread(target=runhub, args=(urcd,)).start()
    
def main():
    import argparse
    ap = argparse.ArgumentParser()

    ap.add_argument('--log', type=str, default='warn')
    ap.add_argument('--irc', type=str, default='127.0.0.1')
    ap.add_argument('--irc-port', type=int, default=6667)
    ap.add_argument('--no-socks', action='store_const', const=True, default=False)
    ap.add_argument('--socks-host', type=str, default='127.0.0.1')
    ap.add_argument('--socks-port', type=str, default=9150)
    ap.add_argument('--remote-hub', type=str, default='psii2p655trtnvru.onion')
    ap.add_argument('--remote-hub-port', type=int, default=6789)
    ap.add_argument('--hubs-file', type=str, default=None)
    ap.add_argument('--hub', type=str, default='127.0.0.1')
    ap.add_argument('--hub-port', type=int, default=6789)
    ap.add_argument('--sign',type=str, default='no')
    ap.add_argument('--name', type=str, default='urc.py')
    ap.add_argument('--no-anon', action='store_const', const=True, default=False)
    
    args = ap.parse_args()

    loglvl = get_log_lvl(args.log) or logging.WARN

    logging.basicConfig(level = loglvl, format='%(asctime)s [%(levelname)s] %(name)s : %(message)s')

    urcd = URCD(sign=args.sign.lower() == 'yes', name=args.name)
    urcd.use_socks = not args.no_socks
    if urcd.use_socks:
        urcd.socks_host = args.socks_host
        urcd.socks_port = args.socks_port
    try:
        urcd.bind_ircd(args.irc, args.irc_port)
        if args.no_anon:
            urcd.ircd.anon = False
        urcd.connect_hub(args.remote_hub, args.remote_hub_port)
        if args.hub:
            urcd.bind_hub(args.hub, args.hub_port)
        if args.hubs_file:
            with open(args.hubs_file) as f:
                for line in f:
                    line = line.replace(' ', '').replace('\n', '').replace('\r', '')
                    if len(line) == 0 or line[0] == '#':
                        continue
                    parts = line.split(':')
                    host = parts[0]
                    port = 6789
                    if len(parts) == 2:
                        port = int(parts[1])
                    urcd.connect_hub(host, port)
        urcd.start()
        urcd.loop.run_forever()
    finally:
        urcd.loop.close()


if __name__ == '__main__':
    if hexchat:
        pass
    else:
        main()
