from scapy.all import send, IP, ICMP

#: ``send()`` function sends packets at Layer 3. (Network layer) Using ``scapy``'s syntax 
#: for packet encapsulation and the builtin ICMP packet generator, a packet is send to
#: the host ``receiver`` with TTL of 1 as per assignment specification.
send(IP(src="sender",dst="receiver",ttl=1)/ICMP())
