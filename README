minimilter
==========

<link rel="stylesheet" href="../style.css" />

This is in HTML at <http://canonical.org/~kragen/sw/minimilter.html>.

This is a very simple [milter](https://www.milter.org/) implementation
in pure Python, including a sample milter.  I'm using this to filter
spam under Postfix on panacea.canonical.org, which is Bad and Wrong
for several reasons:

1. I could do the same thing more easily with sender and recipient
   restrictions.
2. Postfix's "policy service" interface is about a thousand times
   saner than the Milter interface, and performs the same job.
   Writing to the Milter interface does mean that you could, in
   theory, use this with other MTAs that support milters.

About Milters
-------------

Milters are a way to reject or modify mail before it goes into the
mail queue.  I care about this because it lets me bounce spam to its
real sender, not the forged from-address on the mail, so I don't
become part of the backscatter problem.

MTAs that support milters include
[Sendmail](http://www.sendmail.org/),
[Postfix](http://www.postfix.org), and
[qpsmtpd](http://smtpd.develooper.com/).

Sendmail includes `libmilter`, which lets you write milters in C.

I'm using the sample milter to bounce unauthorized mail to some
Mailman mailing lists, on a machine with Postfix, so that our server
doesn't generate backscatter.  I'm probably going to switch away from
it shortly because it turns out Postfix has a built-in feature that
does more or less the same thing.

About Backscatter
-----------------

Backscatter is when spam sent from a forged `From` address gets
bounced back to that address, effectively turning the spam's first
recipient into an inadvertent spam source.  To avoid creating
backscatter, don't bounce mail after accepting it; instead, refuse the
mail at SMTP-time.

Getting it
----------

    git clone http://canonical.org/~kragen/mailman-milter.git

Me
--

Kragen Javier Sitaker <kragen@canonical.org>
