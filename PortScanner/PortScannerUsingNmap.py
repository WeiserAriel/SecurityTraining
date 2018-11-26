#!/usr/bin/python
'''
#written by Ariel Weiser 2018
'''

import optparse
import nmap
import os
from socket import *


def nmapScan(tgtHost, tgtPort):
	nmScan = nmap.PortScanner()
	nmScan.scan(tgtHost, tgtPort)
	state=nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
	print (" [*] " + tgtHost + " tcp/"+tgtPort+" " +state)

def main():
	parser = optparse.OptionParser('%prog -H <target host> -p <target port>')
	parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', help='specify target ports seperated by commas <eg: 443, 21,22,80>')
	(options, args) = parser.parse_args()
	try:
	#from SOCKET Module
		tgtHost = gethostbyname(options.tgtHost)
	except:
		print ("[-] Cannot resolve '%s': Unknown host" %  tgtHost_
		exit(0)
	print ('\n[+] ' + options.tgtHost + ' resolved to ' + str(tgtHost) + '\n')
	tgtPorts = str(options.tgtPort).split(',')

	if (tgtHost == None) | (tgtPorts[0] == None):
		print (parser.error('Invalid Arguments.'))
		exit(0)
	for tgtPort in tgtPorts:
		nmapScan(tgtHost, tgtPort)

if __name__ == '__main__':
	main()
