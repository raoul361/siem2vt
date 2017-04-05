#!/usr/bin/env python

import virustotal
import argparse
import syslog

__author__ = "Raoul Endresl"
__copyright__ = "Copyright 2017"
__license__ = "BSD"
__version__ = "0.1"
__status__ = "Prototype"

# Get of my damn API_KEY. Free API, register at virustotal.com
API_KEY = "[INSERT API KEY HERE]"

parser = argparse.ArgumentParser(description='Searches for a given hash on VirusTotal, sends the result to syslog.')
parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true", default=False)
parser.add_argument("hash", help="file to search for MD5 hashes")
parser.add_argument("engine", help="AV engine to use for taxonomy")
parser.add_argument("message", help="syslog prefix message")

args = parser.parse_args()


v = virustotal.VirusTotal(API_KEY,0)

if args.verbose:
    print """
      _                ____        _   
  ___(_) ___ _ __ ___ |___ \__   _| |_ 
 / __| |/ _ \ '_ ` _ \  __) \ \ / / __|
 \__ \ |  __/ | | | | |/ __/ \ V /| |_ 
 |___/_|\___|_| |_| |_|_____| \_/  \__|                                      
"""

    print "[+] searching for hash: " + args.hash


report = v.get( args.hash )	

if report.done:
	if report.positives > 0:
		engineresult = report.scans[args.engine]
		if args.verbose:
			print "[*] match on hash " + args.hash 
			print "[*] VirusTotal score: ", report.positives
			print "[*] result: " + engineresult["result"]
		
		syslogmessage = args.message + " [hash:" + args.hash + "] [result:" + engineresult["result"] + "] [positives:" + str(report.positives) +"]"
		syslog.syslog(syslog.LOG_ALERT, syslogmessage)
	elif args.verbose:
		print "[-] clean: " + args.hash
