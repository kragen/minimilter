#!/usr/bin/python
"""Make email whitelists from a list of recipients on the command line
and a list of senders on stdin."""
import sys, pprint

def anglize(addr):
    "Wrap angle brackets around an address if it doesn't have 'em."
    if addr.startswith('<'): return addr
    return '<%s>' % addr

senders = [anglize(line.strip()) for line in sys.stdin]
recipients = sys.argv[1:]
whitelists = dict((recipient, senders) for recipient in recipients)
pprint.pprint(whitelists)
