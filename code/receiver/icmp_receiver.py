from scapy.all import sniff

sniff(filter="icmp", count=1).show()
