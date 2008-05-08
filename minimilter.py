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

I implemented this in three hours one morning.

"""

import struct, sys, thread, socket, cgitb
cgitb.enable(format='text')

def ok(a, b):
    "One-line unit testing function."
    assert a == b, (a, b)


## Basic constants.

class smfir:
    """Namespace for reply codes."""
    addrcpt, delrcpt, accept, replbody, continue_ = '+-abc'
    discard, addheader, chgheader, progress, quarantine = 'dhmpq'
    reject, tempfail, replycode = 'rty'


## Decoding packet contents.

# `dispatch_message` looks for a decoder it can call with the packet
# data and get back an args tuple to apply the appropriate method to.
# Parser objects are fancy functions that have a "+" method that lets
# you concatenate them.
# XXX make asciz_multiple a Parser?

def asciz_multiple(astr):
    "Extract a bunch of null-terminated strings, in a list, in a tuple."
    return (astr.split('\0')[:-1],)

ok(asciz_multiple("asdf\0fd\0c\0"), (['asdf', 'fd', 'c'],))

class Parser:
    "Base class for parsing objects."
    def __add__(self, other):
        return Concat(self, other)

class Concat(Parser):
    """Parses the concatenation of two data structures."""
    def __init__(self, a, b):
        self.a, self.b = a, b
    def __call__(self, val):
        width = self.a.width(val)
        return self.a(val[:width]) + self.b(val[width:])
    def width(self, val):
        awidth = self.a.width(val)
        return awidth + self.b.width(val[awidth:])

class _uint32(Parser):
    def __call__(self, val):
        return struct.unpack('>L', val)
    def width(self, val): return 4
uint32 = _uint32()

ok(uint32('\0\0\0\3'), (3,))
ok((uint32+uint32)('\0\0\0\3\0\0\0\4'), (3,4))
ok((uint32+uint32+uint32)('\0\0\0\3\0\0\0\4\0\0\0\6'), (3,4,6))

class _remaining(Parser):
    """Sucks up remaining data as a string."""
    def width(self, val): return len(val)
    def __call__(self, val): return (val,)
remaining = _remaining()

ok((uint32 + remaining)("\0\0\0\4boo"), (4, "boo"))

class Milter:
    """An abstract base milter."""
    def smfic_optneg(self, version, actions, protocol):
        "Option negotiation."
        return 'O' + struct.pack('>LLL', version, 0, 0)

decoders = {
    'smfic_mail': asciz_multiple,
    'smfic_rcpt': asciz_multiple,
    'smfic_optneg': uint32 + uint32 + uint32,
}

class Abort(Exception):
    "Raised on SMFIC_ABORT; supposed to reset milter state."
class Quit(Exception):
    "Raised on SMFIC_QUIT; supposed to close connection."

def dispatch_message(milter, message):
    """Parse a message from the MTA and get a response from the milter.

    The message should already have its initial `len` field removed.

    XXX should this move into the Milter class?

    XXX somewhere we need to empacketize things
    """
    command_code = message[0]  # XXX: 0-length message?

    # XXX move these into the Milter object?
    if command_code == 'A': raise Abort # XXX: do the same for SMFIC_BODYEOB?
    if command_code == 'Q': raise Quit

    map = {'M': 'smfic_mail',
           'R': 'smfic_rcpt',
           'O': 'smfic_optneg'}
    selector = map.get(command_code)
    if selector is None: return smfir.continue_
    args = decoders[selector](message[1:])
    return getattr(milter, selector)(*args)

ok(dispatch_message(Milter(), 'O\0\0\0\2\0\0\0\x3f\0\0\0\x7f'),
   'O' '\0\0\0\2' '\0\0\0\0' '\0\0\0\0')

class Incomplete(Exception):
    "Raised when you try to parse an incomplete packet."

def parse_packet(buffer):
    """Given buffer contents, split off a complete packet
    if possible.

    Returns (packetbody, remainingdata) tuple, or raises
    Incomplete.
    """
    length, contents = (uint32 + remaining)(buffer)
    if len(contents) < length: raise Incomplete
    return (contents[:length], contents[length:])


## Top level control of milter protocol.

def loop(input, output, milter_factory):
    "Run one or more milters against abstract input and output."
    buf = ""
    milter = milter_factory()
    while 1:
        buf += input(4096)  # XXX BUG: there might already be a full message

        try:
            message, buf = parse_packet(buf)
        except Incomplete:
            continue

        try:
            answer = dispatch_message(milter, message)
        except Abort:
            milter = milter_factory()
        except Quit:
            return
        else:
            output(answer)

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
