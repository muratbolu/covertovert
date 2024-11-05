from scapy.all import sniff

#: Using the built-in sniffing tools in ``scapy``, we can set a filter for ICMP packages and sniff
#: only one, which is going to be a packet from ``icmp_sender.py``
sniff(filter="icmp", count=1).show()
