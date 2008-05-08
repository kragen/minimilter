#!/usr/bin/python
"""Very simple pure-Python milter implementation.

I'm implementing this from Todd Vierling's wonderful protocol
documentation, 'The Sendmail Milter Protocol, Version 2', version 1.6.
<http://search.cpan.org/src/AVAR/Sendmail-PMilter-0.96/doc/milter-protocol.txt>

I'm going to test it against Postfix, using something like this:

    smtpd_milters = inet:localhost:6869
    milter_default_action = tempfail

See <http://www.postfix.org/MILTER_README.html> for details.

My own purposes are fairly simple, so this is a very limited
implementation.  I am thinking about checking addresses against
Mailman lists:

    from Mailman import MailList
    mlist = MailList.MailList(listname, lock=False)
    addrs = mlist.getRegularMemberKeys() + mlist.getDigestMemberKeys()

This is just a few hours of work.

"""

import struct, sys, thread, socket, cgitb, StringIO
cgitb.enable(format='text')

def ok(a, b):
    "One-line unit testing function."
    assert a == b, (a, b)

def debug(msg): print msg
def debug(msg): pass


## Basic constants.

class smfir:
    """Namespace for reply codes."""
    addrcpt, delrcpt, accept, replbody, continue_ = '+-abc'
    discard, addheader, chgheader, progress, quarantine = 'dhmpq'
    reject, tempfail, replycode = 'rty'

class smfic:
    """Namespace for command codes."""
    mail, rcpt, optneg, quit, abort = 'MROQA'
    macro = 'D'


## Decoding packet contents: generic data handling.

# `dispatch_message` looks for a decoder it can call with the packet
# data and get back an args tuple to apply the appropriate method to.
# Format objects represent binary data formats; they have a "+" method
# that lets you concatenate them, and you can .encode() or .decode()
# to convert between tuples and binary data.

class TooManyValues(Exception):
    "Signals that you've asked a Format to encode more things than it can."
class Incomplete(Exception):
    "Raised when you try to decode an incomplete data structure."

class Format:
    "Base class for parsing objects."
    def __add__(self, other):
        return Concat(self, other)
    def encode(self, args):
        encoded, extra = self.partial_encode(args)
        if extra: raise TooManyValues
        return encoded

class Remaining(Format):
    """Sucks up remaining data as a string."""
    def width(self, val): return len(val)
    def decode(self, val): return (val,)
    def partial_encode(self, args):
        return args[0], args[1:]
remaining = Remaining()

class AscizMultiple(Remaining):
    "Parses a bunch of null-terminated strings as a string list."
    def decode(self, val):
        return (val.split('\0')[:-1],)
    def partial_encode(self, args): raise "Unimplemented"
asciz_multiple = AscizMultiple()

ok(asciz_multiple.decode("asdf\0fd\0c\0"), (['asdf', 'fd', 'c'],))

class Concat(Format):
    """Parses the concatenation of two data structures."""
    def __init__(self, a, b):
        self.a, self.b = a, b
    def decode(self, val):
        width = self.a.width(val)
        return self.a.decode(val[:width]) + self.b.decode(val[width:])
    def width(self, val):
        awidth = self.a.width(val)
        return awidth + self.b.width(val[awidth:])
    def partial_encode(self, args):
        a_encoded, a_extra = self.a.partial_encode(args)
        b_encoded, b_extra = self.b.partial_encode(a_extra)
        return a_encoded + b_encoded, b_extra

class _uint32(Format):
    def decode(self, val):
        try:
            return struct.unpack('>L', val)
        except struct.error, e:
            raise Incomplete(e)
    def width(self, val): return 4
    def partial_encode(self, args):
        return struct.pack('>L', args[0]), args[1:]
uint32 = _uint32()

ok(uint32.decode('\0\0\0\3'), (3,))
ok((uint32+uint32).decode('\0\0\0\3' '\0\0\0\4'), (3,4))
ok((uint32+uint32+uint32).decode('\0\0\0\3' '\0\0\0\4' '\0\0\0\6'), (3,4,6))
ok((uint32+uint32+uint32).encode((3,4,6)), '\0\0\0\3' '\0\0\0\4' '\0\0\0\6')
ok((uint32 + remaining).decode("\0\0\0\4boo"), (4, "boo"))
ok((uint32 + remaining).encode((4, "boo")), "\0\0\0\4boo")


## Decoding packet contents: milter protocol data formats.

# I follow Vierling's terminology: the globs sent over the socket
# including the leading byte count is a "packet", and the content of
# such a glob (which begins with an opcode byte) is a "message".

smfic_optneg_format = uint32 + uint32 + uint32

class Milter:
    """An abstract base milter."""
    def smfic_optneg(self, version, actions, protocol):
        "Option negotiation."
        return 'O' + smfic_optneg_format.encode((version, 0, 0))

decoders = {
    'smfic_mail': asciz_multiple,
    'smfic_rcpt': asciz_multiple,
    'smfic_optneg': smfic_optneg_format,
}

class Abort(Exception):
    "Raised on SMFIC_ABORT; supposed to reset milter state."
class Quit(Exception):
    "Raised on SMFIC_QUIT; supposed to close connection."

packet_format = uint32 + remaining
def empacketize(val):
    return packet_format.encode((len(val), val))

def _dispatch_message(milter, message):
    # XXX I think the handling of zero-length messages here is okay:
    # The exception propagates up the stack and kills the milter
    # server thread, and hopefully gets logged.  The same thing
    # happens if a decoder below raises Incomplete.
    command_code = message[0]
    debug("message %r, %r" % (command_code, message))

    # XXX move these into the Milter object?
    if command_code == smfic.abort:
        raise Abort # XXX: do the same for SMFIC_BODYEOB?
    if command_code == smfic.quit:
        raise Quit
    if command_code == smfic.macro:
        return []

    map = {smfic.mail: 'smfic_mail',
           smfic.rcpt: 'smfic_rcpt',
           smfic.optneg: 'smfic_optneg'}
    selector = map.get(command_code)
    if selector is None: return smfir.continue_
    args = decoders[selector].decode(message[1:])
    debug("got message %r => %s%s" % (command_code, selector, args))
    return getattr(milter, selector)(*args)

def dispatch_message(milter, message):
    """Parse a message from the MTA and get a response from the milter.

    The message should already have its initial `len` field removed.

    XXX should this move into the Milter class?

    """
    response = _dispatch_message(milter, message)
    if not isinstance(response, list): response = [response]
    return ''.join(map(empacketize, response))

ok(smfic.optneg, 'O')
ok(dispatch_message(Milter(), 'O' '\0\0\0\2' '\0\0\0\x3f' '\0\0\0\x7f'),
   '\0\0\0\x0d' 'O' '\0\0\0\2' '\0\0\0\0' '\0\0\0\0')

def parse_packet(buffer):
    """Given buffer contents, split off a complete packet
    if possible.

    Returns (packetbody, remainingdata) tuple, or raises
    Incomplete.
    """
    # It's a little misleading that we use packet_format here --- the
    # actual packet may end before the end of the buffer.
    length, contents = packet_format.decode(buffer)
    if len(contents) < length: raise Incomplete
    # So we slice it here.
    return (contents[:length], contents[length:])

ok(parse_packet('\0\0\0\4abcde'), ('abcd', 'e'))


## Control flow of milter protocol.

def loop(input, output, milter_factory):
    "Run one or more milters against abstract input and output."
    buf = ""
    milter = milter_factory()
    while 1:
        try:
            message, buf = parse_packet(buf)
        except Incomplete:
            data = input(4096)
            debug("got %r" % data)
            if not data:
                return
            buf += data
            continue

        try:
            answer = dispatch_message(milter, message)
        except Abort:
            milter = milter_factory()
        except Quit:
            return
        else:
            debug("responding with %r" % answer)
            output(answer)

_testresponses = []
_source = StringIO.StringIO(
    # this is a little dodgy because we wouldn't ever really get
    # multiple smfic_optneg packets
    empacketize(smfic.optneg + smfic_optneg_format.encode((2, 0x3f, 0x7f))) +
    empacketize(smfic.optneg + smfic_optneg_format.encode((3, 0x3f, 0x7f))) +
    empacketize(smfic.quit))
loop(_source.read, _testresponses.append, Milter)
ok(_testresponses, [
    empacketize(smfic.optneg + smfic_optneg_format.encode((2, 0, 0))),
    empacketize(smfic.optneg + smfic_optneg_format.encode((3, 0, 0)))])

# tests to make sure unexpected EOF is handled in some way other than
# just spinning.
loop(StringIO.StringIO("").read, "expect no responses", Milter)
loop(StringIO.StringIO("\0\0\0\1").read, "expect no responses", Milter)

# A test with real data from Postfix 2.3.8-2+b1
_realdata = ('\0\0\0\rO\0\0\0\x02\0\0\0=\0\0\0\x7f'
             '\0\0\0VDCj\0watchdog-qemu-image.local\0{daemon_name}\0'
             'watchdog-qemu-image.local\0v\0Postfix 2.3.8\0'
             '\x00\x00\x00\x18Clocalhost\x004\x00\x00127.0.0.1\x00')
_testresponses = []
loop(StringIO.StringIO(_realdata).read, _testresponses.append, Milter)
ok(_testresponses, [
    empacketize(smfic.optneg + smfic_optneg_format.encode((2, 0, 0))),
    '',                # no response for D (macro definition) messages
    empacketize(smfir.continue_)])

# test for commands with default handling (again, real data from Postfix)
_realdata2 = '\x00\x00\x00\x02DH\x00\x00\x00\x1aHthis-is-my-helo-hostname\x00'
_testresponses = []
loop(StringIO.StringIO(_realdata2).read, _testresponses.append, Milter)
ok(_testresponses, ['', empacketize(smfir.continue_)])


def socket_loop(sock, milter_factory):
    "Run one or more milters on an open socket connection."
    loop(sock.recv, sock.send, milter_factory)
    print "connection closed"
    sock.close()

def threaded_server(port, milter_factory):
    "Run a threaded server on localhost."
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sockaddr = ('127.0.0.1', port)
    sock.bind(sockaddr)
    sock.listen(5)

    print "listening on", sockaddr

    while 1:
        (conn, addr) = sock.accept()
        # XXX is there a chance of resource exhaustion here?
        thread.start_new_thread(socket_loop, (conn, milter_factory))
        del conn                        # for GC


## My specific milter.
# Eventually this should go into a file of its own.

class RecipMapMilter(Milter):
    """A simple milter that filters on allowed senders for
    some recipients.

    For recipients not in the map, all senders are allowed.

    For recipients in the map, only specified senders are
    allowed.

    """
    def __init__(self, recipmap):
        self.recipmap = recipmap
    def smfic_mail(self, strings):
        "Respond to a MAIL FROM: command."
        self.sender = strings[0]
        print "sender is", self.sender
        return smfir.continue_
    def smfic_rcpt(self, strings):
        "Respond to an RCPT TO: command."
        recip = strings[0]
        print "recipient is", recip
        if recip in self.recipmap and self.sender not in self.recipmap[recip]:
            return smfir.reject
        else:
            return smfir.continue_

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print "usage: %s <mapfile> <portnum>" % (sys.argv[0])
    else:
        recipmap = eval(file(sys.argv[1]).read())
        threaded_server(int(sys.argv[2]),
                        lambda: RecipMapMilter(recipmap))
