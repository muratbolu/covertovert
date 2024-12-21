from CovertChannelBase import CovertChannelBase

from scapy.all import IP, UDP, DNS, sniff

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """

    sender_ip = "172.18.0.2"
    receiver_ip = "172.18.0.3"
    port = 12345
    bits = ""
    message = ""

    def __init__(self):
        """
        - You can edit __init__.
        """
        pass

    def send(self, log_file_name, parameter1, parameter2):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for b in binary_message:
            # TODO: delete print
            # print(b)
            bit = 0 if b == '0' else 1
            packet = IP(dst=self.receiver_ip) / UDP(dport=self.port) / DNS(tc=bit)
            CovertChannelBase.send(self, packet)

    def stop_condition(self, packet):
        return len(self.message) > 0 and self.message[-1] == '.'

    def packet_handler(self, packet):
        if UDP in packet and packet[UDP].dport == self.port:
            tc = packet[DNS].tc
            self.bits += "0" if tc == 0 else "1"
            if len(self.bits) == 8:
                # print(f"Bits: {self.bits}")
                self.message += CovertChannelBase.convert_eight_bits_to_character(self, self.bits)
                # print(f"Message: {self.message}")
                self.bits = ""

    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """

        sniff(iface="eth0", prn=self.packet_handler, stop_filter=self.stop_condition, filter=f"udp port {self.port}")
        self.log_message(self.message, log_file_name)
