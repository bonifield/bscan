#!/usr/bin/python3


# https://github.com/bonifield/bscan
# v0.3 - 05 Oct 2019
#	- added dns scan mode and dnsquery argument (better results than udp mode when scanning port 53)
#	- added output modes:  color, pipe, tsv, csv, none
#	- added additional xmas scan mode logic when receiving ICMP
#	- added additional UDP scan mode logic
#	- made all sendCheck() return values into dictionaries
#	- switched to argparse instead of optparse
# v0.2 - 11 May 2019 - threading
# v0.1 - 05 May 2019 - ripped only scanner components from adaptive-scanner, no need for the CTF modules
# ---
# sudo tcpdump -nn -s0 -i any
# port states (not code) based on these links:
#	https://nmap.org/book/man-port-scanning-techniques.html
#	https://resources.infosecinstitute.com/port-scanning-using-scapy/
# threading help via https://www.tutorialspoint.com/python3/python_multithreading.htm
# scan types ("modes" in this tool) supported - syn xmas fin null ack udp dns
# TODO - only import necessary Scapy functions
# TODO - improve "dns" mode, based on https://thepacketgeek.com/scapy-p-09-scapy-and-dns/
# TODO - support for IP hyphenated ranges, ex. 10.1.2.3-10
# TODO - IPv6 single address and CIDR support (IPv6Helper)
# TODO - user-specified number of threads, queues
# TODO - improve argparse help statements and then deprecate helpy()
# TODO - arping integration


import argparse, json, logging, sys, threading
#, time
from random import randint
# disable the Scapy IPv6 warning, must go above Scapy import
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# all Scapy features
from scapy.all import *


# allows script to still work if IPv4Helper isn't found
nocidrsupport = False
try:
	from IPv4Helper import *
except:
	print('WARNING - did not find the module IPv4Helper')
	nocidrsupport = True


modes = {"syn":"S", "xmas":"FPU", "fin":"F", "null":"", "ack":"A", "udp":""}
acceptedoutputstyles = ["color", "pipe", "tsv", "csv", "json", "none"]


# TODO - deprecate this function once argparse help statements are improved upon
def helpy():
	print()
	print('Usage:')
	print('\tbscan.py -i [IP] -p [port1,port2,port3-port10,etc] -m [mode]')
	print()
	print('\tAvailable scan modes:  syn, xmas, fin, null, ack, udp, dns')
	print('\t\t- UDP scanning is hit-or-miss depending on service; best to use DNS mode or other service-specific packets')
	print()
	print('\t-i / --ip\t\tIP address or CIDR (CIDR = scanner mode only)')
	print('\t-p / --port\t\tports, comma-separated')
	print('\t-m / --mode\t\tscan modes')
	print('\t\t-q / --dnsquery\tdomain to query, only use with -m dns')
	print('\t-d / --data\t\tOPTIONAL: add x null bytes; defaults to 0 byte payload')
	print('\t-t / --timeout\t\tOPTIONAL: add timeout; defaults to 1 second')
	print('\t-y / --outputstyle\tOPTIONAL:  color (default), pipe, tsv, csv, json, none')
	print('\t\t color and none outputstyles are delimited by tab, but do not include the TSV header')
	print()
	print('Examples:')
	print('\tbscan.py -i 192.168.1.10 -p 80,443 -m syn -t 2')
	print('\tbscan.py -i 192.168.1.10/28 -p 80,443 -m syn -y csv')
	print('\tbscan.py --ip=192.168.1.10 --port=80,443 --mode=syn --timeout=2 --data=50')
	print('\tbscan.py -i 192.168.1.10/28 -p 80,100-200,443 -m syn -d 50')
	print('\tbscan.py -i 192.168.1.10 -p 53 -m udp -y json')
	print('\tbscan.py -i 192.168.1.10 -p 53,5353 -m dns -q stackoverflow.com')
	print()
	print('Defaults if no flags are specified (only specify an IP if 80/syn mode is needed):')
	print('\tip:  127.0.0.1')
	print('\tport:  80')
	print('\tmode:  syn')
	print('\tdata:  0')
	print('\ttimeout:  0.15')
	print('\toutputstyle:  color')
	print()


def portfixer(parg):
	''' returns a list of ports for the scanner function to process '''
	ports = []
	for p in parg:
		if '-' in p:
			x = p.split('-')
			for r in range(int(x[0]), int(x[1])+1):
				ports.append(r)
		else:
			ports.append(int(p))
	return list(set(ports))


def ipfixer(i):
	''' creates a generator object for all IPs in a given subnet, requires the IPv4Helper module from github.com/bonifield '''
	if '/' in i:
		if not nocidrsupport:
			return IPv4Helper(str(i)).ip_range_generator()
		else:
			print('ERROR - no CIDR support - library IPv4Helper not found')
			print('please check:')
			print('https://github.com/bonifield/IPv4Helper')
			sys.exit(1)
	else:
		return i


parser = argparse.ArgumentParser(description="Simple Python Network Scanner")
parser.add_argument("-i", "--ip", dest="ip", default="127.0.0.1", type=str, help="specify a single IP or CIDR range", required=True)
parser.add_argument("-p", "--port", dest="port", default=80, help="specify one or more ports, ex. just 80 or 80,443,8000-8080", required=True)
parser.add_argument("-m", "--mode", dest="mode", default="syn", type=str, help="supported modes:  syn xmas fin null ack udp dns", choices=["syn", "xmas", "fin", "null", "ack", "udp", "dns"], required=True)
parser.add_argument("-q", "--dnsquery", dest="dnsquery", default="google.com", type=str, help="domain to query, use only in dns mode")
parser.add_argument("-d", "--data", dest="data", default=0, type=int, help="add X null bytes, defaults to a 0-byte payload in TCP modes")
parser.add_argument("-s", "--stringpayload", dest="spay", type=str, help="specify string payload for TCP modes")
parser.add_argument("-t", "--timedelay", dest="timeout", default=0.15, type=float, help="time delay in ms")
parser.add_argument("-y", "--outputstyle", dest="outputstyle", default="color", type=str, help="specify output style:  color (default), pipe, tsv, csv, json, none", choices=["color", "pipe", "tsv", "csv", "json", "none"])
args = vars(parser.parse_args())
ip = ipfixer(args["ip"])
port = portfixer(args["port"].split(','))
mode = args["mode"]
data = args["data"]
spay = args["spay"]
timeout = args["timeout"]
#payl = args["payl"]
outputstyle = args["outputstyle"]
dnsquery = args["dnsquery"]


class tcol:
	PURPLE = '\033[95m'
	GREEN = '\033[92m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	BGGOLD = '\033[33;7m'
	BGYELLOW = '\033[93;7m'
	BGRED = '\033[91;7m'
	BGBLUE = '\033[94;7m'
	BGGREEN = '\033[92;7m'
	RESET = '\033[0m'


class Scanny(threading.Thread):
	def __init__(self, tid, ip, port, mode, timeout, pkt):
		threading.Thread.__init__(self)
		self.tid = tid
		self.ip = ip
		self.port = port
		self.mode = mode
		self.timeout = timeout
		self.pkt = pkt
	def run(self):
		z = sendCheck(self.pkt, self.mode, self.timeout)
		outputstylePrinter(self.ip, self.port, self.mode, z['state'], z['message'])


def outputstylePrinter(ip, port, mode, state, message):
	''' prints based on outputstyle argument; called from instance of Scanny class '''
	s = state
	delim = "\t"
	# change delim as needed
	if outputstyle == "pipe":
		delim = "|"
	elif outputstyle == "tab":
		delim = "\t"
	elif outputstyle == "csv":
		delim = ","
	# add color if needed
	if outputstyle == "color":
		if "open" in state:
			s = str(tcol.BOLD+tcol.GREEN+s+tcol.RESET)
		elif "filtered" in state:
			s = str(tcol.PURPLE+s+tcol.RESET)
		elif "closed" in state:
			s = str(tcol.RED+s+tcol.RESET)
		else:
			s = state
	if outputstyle == "json":
		# print json
		print(json.dumps({"ip":ip, "port":port, "mode":mode, "state":state, "message":message}))
	else:
		# print non-json
		print("{}{}{}{}{}{}{}{}{}".format(ip, delim, port, delim, mode, delim, s, delim, message))


def sendCheck(pkt, mode, tout):
	''' sr1() and packet open/filtered/closed logic '''
	x = sr1(pkt, retry=0, timeout=float(tout), verbose=False)
	if type(x).__name__ == 'NoneType':
		if mode == 'syn':
			return {'state':'filtered', 'message':'no response'}
		elif mode == 'xmas' or mode == 'fin' or mode == 'null':
			return {'state':'open', 'message':'no response possibly filtered'}
		elif mode == 'ack':
			return {'state':'filtered', 'message':'no response'}
		elif mode == 'udp':
			return {'state':'closed', 'message':'no response try protocol specific packets'}
		elif mode == 'dns':
			return {'state':'closed', 'message':'no response try protocol specific packets'}
	elif x.haslayer('TCP'):
		r = x.sprintf('%TCP.flags%')
		if 'SA' in r:
			return {'state':'open', 'message':str('received {}'.format(r))}
		elif 'R' in r:
			if mode == 'ack':
				return {'state':'unfiltered', 'message':str('window size {} unsure if open or closed'.format(x['TCP'].window))}
			else:
				return {'state':'closed', 'message':str('received {}'.format(r))}
		else:
			return {'state':'other_TCP', 'message':str('received {}'.format(r))}
	elif x.haslayer('UDP'):
		if mode == 'udp':
			return {'state':'open', 'message':'received UDP packet'}
		if mode == 'dns':
			try:
				dnsqa = str('/'.join(x[UDP][DNS][DNSRR][i].rdata for i in range(x[UDP][DNS].ancount)))
				#return {'state':'open', 'message':'received DNS response{}'.format(str("s "+dnsqa))}
				return {'state':'open', 'message':'{} at {}'.format(dnsquery, dnsqa)}
			except:
				return {'state':'open', 'message':'received UDP packet'}
	elif x.haslayer('ICMP'):
		ty = x['ICMP'].type
		co = x['ICMP'].code
		if mode == 'udp':
			if ty == 3 and co == 3:
				return {'state':'closed', 'message':str('received ICMP type {} code {}'.format(ty, co))}
			elif ty == 3 and co in [0,1,2,9,10,13]:
				return {'state':'filtered', 'message':str('received ICMP type {} code {}'.format(ty, co))}
		if mode == 'xmas' or mode == 'fin' or mode == 'null':
				return {'state':'filtered', 'message':str('received ICMP type {} code {}'.format(ty, co))}
		else:
			if ty == 3:
				return {'state':'filtered', 'message':str('received ICMP type {} code {}'.format(ty, co))}
			else:
				return {'state':'other_ICMP', 'message':str('received ICMP type {} code {}'.format(ty, co))}
	else:
		return {'state':'other', 'message':'other'}
		#x.show()


def printColumnHeaders():
	''' changes output header based on outputstyle argument '''
	if outputstyle == "color":
		print(tcol.BGBLUE + tcol.BOLD +'IP              PORT    MODE    STATE            MESSAGE' + " "*40 +tcol.RESET)
	elif outputstyle == "none":
		print('='*70)
		print('IP\t\tPORT\tMODE\tSTATE\t\tMESSAGE\t\t')
		print('='*70)
	elif outputstyle == "pipe":
		print('ip|port|mode|state|message')
	elif outputstyle == "tsv":
		print('ip\tport\tmode\tstate\tmessage')
	elif outputstyle == "csv":
		print('ip,port,mode,state,message')


def main():
#	t1 = time.time()
	printColumnHeaders()
	threads = []
	tid = 1
	# loop over all IPs in a subnet, if one was provided
	pad = "0"*int(data)
	if type(ip).__name__ == 'generator':
		for i in ip:
			# loop over all ports
			for p in port:
				if mode == "arp":
					#pkt = Ether(src="de:ad:be:ef:f0:0d",dst="ff:ff:ff:ff:ff:ff"
					pkt = ARP(op=ARP.who_has, psrc="192.168.69.69", pdst="{}".format(i))
				if mode == "dns":
					pkt = IP(dst="{}".format(i))/UDP(sport=randint(1025,65535),dport=int(p))/DNS(rd=1,qd=DNSQR(qname=str(dnsquery)))
				if mode == "udp":
					pkt = IP(dst="{}".format(i))/UDP(sport=randint(1025,65535),dport=int(p))
				if mode in ["syn", "xmas", "ack", "null"]:
					pkt = IP(dst="{}".format(i))/TCP(sport=randint(1025,65535),dport=int(p),flags="{}".format(modes[mode]))/Raw(load=pad)
				s = Scanny(tid, i, p, mode, timeout, pkt)
				s.start()
				threads.append(s)
				tid += 1
	# just use a single IP if no subnet was provided
	elif type(ip).__name__ == 'str':
		for p in port:
			if mode == "dns":
				pkt = IP(dst="{}".format(ip))/UDP(sport=randint(1025,65535),dport=int(p))/DNS(rd=1,qd=DNSQR(qname=str(dnsquery)))
			elif mode == "udp":
				pkt = IP(dst="{}".format(ip))/UDP(sport=randint(1025,65535),dport=int(p))
			else:
				# default to TCP packet
				pkt = IP(dst="{}".format(ip))/TCP(sport=randint(1025,65535),dport=int(p),flags="{}".format(modes[mode]))/Raw(load=pad)
			s = Scanny(tid, ip, p, mode, timeout, pkt)
			s.start()
			threads.append(s)
			tid += 1
	for t in threads:
		t.join()
#	t2 = time.time()
#	print(t2-t1)
	sys.exit(1)


if __name__ == "__main__":
	main()
