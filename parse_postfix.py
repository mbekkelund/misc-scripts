#!/usr/bin/env python
#
# This script was written to discover suspicious activity coming from 
# our companys mailboxes. Suddenly one guy had sent close to 40k mails
# in a week and we started getting blocked here and there on da interwebs :)
#
# The "suspicious" threshold will differ from place to place, so you have 
# to find a reasonable value yourself.
#
# Will be rewritten as a nagios-plugin later(tm) 
#

import re
import datetime
import argparse



skip_users = ['root','www','nagios','pgsql','noreply'] # stuff we might not be interested in having in our output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Options:')
    parser.add_argument('-s', metavar='suspicious', type=int, help='set amount of mails sent before reporting suspicious activity', required=False, default=555)
    parser.add_argument('-m', metavar='multiply', type=bool, help='set to true if the suspicious value should be multiplied by weekday (since the log grows pr day)', required=False, default=True)
    parser.add_argument('-l', metavar='logfile', type=str, help='full path of the mail.log logfile (default=/var/log/mail.log)', required=False, default="/var/log/mail.log")
    parser.add_argument('-d', metavar='debug', type=bool, help='turn debugging on/off', required=False, default=False)
    parser.add_argument('-u', metavar='skipusers', type=str, help='commaseparated list of users not to include in the output', required=False)

    try:
        arguments = parser.parse_args()
    except Exception as e:
        print "Error in argumentparsing: {0}".format(e)
        sys.exit(1)

    # since logrotation happens on sunday morning, we'll multiply the suspicious-value by weekday
    # this mismatches a little on sundays (sundays being day 6 in python and logrotation might
    # be happening in the mornings :P ..adjust it or fix the script)
    if arguments.m:
        arguments.s = arguments.s * datetime.datetime.today().weekday() 

    if arguments.u:
        for u in arguments.u.split(","):
            skip_users.append(u)

    senders = dict()
    maillog = open(arguments.l, 'r').readlines()

    for line in maillog:
        
        if re.search("(?<=from=<)\w+", line):
            m = re.search('\w+@[\w.-]+', line)
            if m:
                sender = m.group(0)
                user   = sender.split("@")[0] # need this for skip_users matching

                if not user in skip_users: 
                    if senders.get(sender):
                        senders[sender] = senders.get(sender) + 1
                    else:
                        senders[sender] = 1

    if arguments.d:
        print "=== Settings: ==="
        print "Using logfile: {0}".format(arguments.l)
        print "Suspicious activity is currently set to {0} mails sent.".format(arguments.s)
        print "Skipping users: {0}".format(skip_users)
        print "=== Users and values: ==="

    for s in sorted(senders, key=senders.get, reverse=False):
        if senders[s] > arguments.s:
            print "{0} : {1}".format(s,senders[s])

