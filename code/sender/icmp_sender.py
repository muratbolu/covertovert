from scapy.all import send, IP, ICMP

send(IP(src="sender",dst="receiver",ttl=1)/ICMP())
