#!/usr/bin/env python3.4
# 
# urc.py
#
# monolithic urcd in python because urcd sucks ass
#
# public domain
#
import ctypes
import struct
import asyncio
from random import randrange
import time
import logging
import os

rand = lambda n : os.urandom(n)

# i don't like regular expressions
import re  

# -- begin lameass regexp block

_RE_CHARS = 'a-zA-Z0-9\.\\|\\-_~'
_RE_CHAN_PREFIX = '[&#+]'
_RE_CHAN = '%s+[%s]+' % (_RE_CHAN_PREFIX, _RE_CHARS)
_RE_NICK = '[%s]+' % _RE_CHARS
_RE_SRC = '[%s]+![~%s]+@[%s]+' % ( (_RE_CHARS, ) * 3)
_RE_CMD = '[A-Z]+'
_RE_URCLINE = '^:(%s) (%s) ?(%s|%s) :(.+)$' % (_RE_SRC, _RE_CMD, _RE_CHAN, _RE_NICK)

_RE_NICK_CMD = '^NICK (%s)' % _RE_NICK
_RE_USER_CMD = '^USER %s %s %s :(%s)' % ( (_RE_NICK, ) * 4)
_RE_PRIVMSG_CMD = '^PRIVMSG (%s|%s) :(.+)$' % (_RE_NICK, _RE_CHAN)
_RE_JOIN_CMD = '^JOIN (%s)' % _RE_CHAN
_RE_PART_CMD = '^PART (%s) :(.+)$' % _RE_CHAN
_RE_QUIT_CMD = '^QUIT (.+)$'
_RE_LIST_CMD = '^LIST'
_RE_PING_CMD = '^PING (.*)$' 

# -- end lameass regexp block

# -- begin irc functions

def _irc_re_parse(regex, line):
    m = re.match(regex, line)
    if m:
        return m.groups()

irc_parse_nick = lambda line : _irc_re_parse(_RE_NICK_CMD, line)
irc_parse_user = lambda line : _irc_re_parse(_RE_USER_CMD, line)
irc_parse_privmsg = lambda line : _irc_re_parse(_RE_PRIVMSG_CMD, line)
irc_parse_join = lambda line : _irc_re_parse(_RE_JOIN_CMD, line)
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

def taia96n_now():
    """
    get unnecessarily accurate timestamp for time right now
    """
    now = time.time()
    sec = int(4611686018427387914) + int(now)
    nano = int(1000000000*(now%1)+randrange(0,512))
    return struct.pack('<QI', sec, nano)

def taia96n_parse(data):
    """
    parse unnecessarily accurate timestamp
    """
    if len(data) != 12: return None
    return struct.unpack('<QI',data)

def filter_urcline_chars(string, filler='*'):
    """
    filter undesirable characters out of urcline string
    """
    for bad in '\r\n\x00':
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
    data = None
    if pkttype == 0:
        data = bytes()
        data += struct.pack('>H', len(pktdata)) # packet length
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
        yield a hub packet tuple , (data, sig)
        does not verify
        """
        data = yield from self.r.readexactly(2)
        pktlen = struct.unpack('>H', data)[0]
        data = yield from self.r.readexactly(12)
        tsec, tnano = taia96n_parse(data)
        data = yield from self.r.readexactly(4)
        pkttype = struct.unpack('<I', data)[0]
        data = yield from self.r.readexactly(8)
        self.log.debug('read packet len={}'.format(pktlen))
        data = yield from self.r.readexactly(pktlen)
        self.log.info('data={}'.format([data]))
        if pkttype == 1:
            sig = yield from self.r.readexactly(32)
            return data, sig
        elif pkttype == 0:
            return data, None
        else:
            self.log.warn('invalid packet type %d, dropping' % pkttype)
            return None, None

    @asyncio.coroutine
    def send_hub_packet(self,pktdata, pkttype=0):
        """
        send a hub packet, insert timestamp etc
        pktdata must be bytes
        """
        if pkttype != 0:
            self.log.error('cannot send unsupported hub packet of type %d' % pkttype)
            return
        self.log.info('send packet')
        data = mk_hubpkt(pktdata)
        self.log.info('write %d bytes' % len(data))
        self.log.debug('write %s' % [data])
        self.w.write(data)
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
        self.w.writelines([line.encode('utf-8')])
        self.log.debug(' <-- {}'.format(line))
        yield from self.w.drain() 

    @asyncio.coroutine
    def _handle_line(self, line):
        """
        handle a line from irc client
        """
        line = line.decode('utf-8')
        self.log.debug(' --> {}'.format(line))
        _nick = irc_parse_nick(line)
        _user = irc_parse_user(line)
        _join = irc_parse_join(line)
        _part = irc_parse_part(line)
        _quit = irc_parse_quit(line)
        _privmsg = irc_parse_privmsg(line)
        _ping = irc_parse_ping(line)
        
        # PING
        if _ping:
            yield from self.send_line(':{} PONG {}\n'.format(self.urcd.name, _ping[0]))
        # QUIT
        if _quit:
            self.w.write_eof()
            
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
            if _join and _join not in self.chans:
                chan = _join[0]
                self.chans.append(chan)
                line = ':{}!{}@{} JOIN {}\n'.format(self.nick, self.user, self.urcd.name, chan)
                yield from self.send_line(line)
                line = ':{} 353 {} = {} :{}\n'.format(self.urcd.name, self.nick, chan, self.nick)
                yield from self.send_line(line)
                line = ':{} 366 {} {} :RPL_ENDOFNAMES\n'.format(self.urcd.name, self.nick, chan)
                yield from self.send_line(line)
                
            # PART
            if _part and _part in self.chans:
                self.chans.remove(_part)
                line = ':{}!{}@{} PART {}\n'.format(self.nick, self.user, self.urcd.name, chan)
                yield from self.send_line(line)
            
            # PRVIMSG
            if _privmsg:
                dest, msg = _privmsg
                line = ':{}!{}@{} PRIVMSG {} :{}\n'.format(self.nick, self.user, 
                                                         self.urcd.name, dest, msg)
                for irc_user in self.urcd.ircs:
                    if irc_user is not self:
                        yield from irc_user.send_line(line)

                yield from self.urcd.broadcast(line)
        else:
            if self.nick is not None and self.user is not None:
                for line in irc_greet(self.urcd.name, self.nick, self.user, self.urcd.motd()):
                    yield from self.send_line(line)
                self.greeted = True
 
class URCD:
    """
    urcd server context
    """

    def __init__(self, name='urc.uguu.tld'):
        self.name = name
        self.hubs = list()
        self.ircs = list()
        self.ircchans = list()
        self.hooks = list()
        self.loop = asyncio.get_event_loop()
        self.tasks = list()
        inject_log(self)

    @asyncio.coroutine
    def forward_urcline(self, connection, urcline):
        """
        forward URCLINE from connection
        """
        self.log.debug('forward {}'.format(urcline))
        for con in self.hubs:
            if con is not connection:
                yield from con.send_hub_packet(urcline)

    def motd(self):
        yield 'lol'
        yield 'lol'

    @asyncio.coroutine
    def broadcast(self, urcline):
        """
        send urcline to all connection
        """
        if isinstance(urcline, str):
            urcline = urcline.encode('utf-8')
        self.log.info('broadcast {}'.format(urcline))
        for con in self.hubs:
            yield from con.send_hub_packet(urcline)
        
    def _new_hub_connection(self, r, w):
        con = urc_hub_connection(self, r, w)
        self.hubs.append(con)
        self._tick_hub(con)

    def _tick_hub(self, con):
        asyncio.async(self._handle_packet(con))

    def _connect_server(self, host, port):
        self.log.info('connecting...')
        r, w = yield from asyncio.open_connection(host, port)
        self.log.info('connected!')
        self._new_hub_connection(r, w)
 
    def _disconnected(self, con):
        self.log.warn('disconnceted')
        if con in self.hubs:
            self.hubs.remove(con)
        if con in self.ircs:
            self.ircs.remove(con)

    def connect(self, host, port):
        """
        connect out to urc hub
        """
        self.log.info('connecting to {}:{}'.format(host, port))
        asyncio.async(self._connect_server(host, port))

    def _incoming_hub(self, r, w):
        self.log.info('incoming hub connection')
        self._new_hub_connection(r, w)

    def _incoming_irc(self, r, w):
        self.log.info('incoming irc connection')
        con = irc_handler(self, r, w)
        self.ircs.append(con)

    def bind_ircd(self, host, port):
        """
        bind ircd to host:port
        """
        asyncio.async(asyncio.start_server(self._incoming_irc, host, port))
        self.log.info('bind ircd to {}:{}'.format(host,port))

    def bind_hub(self, host, port):
        """
        bind server to host:port
        """
        asyncio.async(asyncio.start_server(self._incoming_hub, host, port))
        self.log.info('bind hub to {}:{}'.format(host,port))
        
    @asyncio.coroutine
    def _handle_packet(self, con):
        self.log.info('handle packet')
        try:
            data, sig = yield from con.get_hub_packet()
        except Exception as e:
            self.log.error(e)
            self._disconnected(con)
            raise e
        else:
            _data = data.decode('utf-8') 
            parsed = parse_urcline(_data)
            if parsed:
                src, cmd, dst, msg = parsed
                self.log.debug((src, cmd, dst, msg))
                if dst is None:
                    dst = msg
                for irc_user in self.ircs:
                    if dst in irc_user.chans:
                        yield from irc_user.send_line(_data)
            else:
                self.log.error('invalid urcline {}'.format(data))
            yield from self.forward_urcline(con, data)
            self.loop.call_soon(self._tick_hub, con)


#logging.basicConfig(level = logging.DEBUG)

import sys
if len(sys.argv) == 1:
    print ('usage: {} hubport [remotehubhost remotehubort]')
else:
    urcd = URCD()
    try:
        urcd.bind_hub('0.0.0.0', sys.argv[1])
        urcd.bind_ircd('127.0.0.1', 6667)
        if len(sys.argv) == 4:
            urcd.connect(sys.argv[2], int(sys.argv[3]))
            urcd.loop.run_forever()
    finally:
        urcd.loop.close()
