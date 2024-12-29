from CovertChannelBase import CovertChannelBase

from scapy.all import IP, UDP, DNS, sniff

class MyCovertChannel(CovertChannelBase):
    """
    The class contains sender and receiver states but the sender and the
    receiver do not observe the opposite states, they keep track of their own
    states with the characters sent and received. The class also contains the
    bits received by the receiver and the message constructed by the receiver.
    """
    sender_state = None
    receiver_state = None
    bits = ""
    message = ""

    def __init__(self):
        pass

    def determine_sending(self, b, state, change_char):
        """
        Determines which symbol to send based on its arguments.
        """
        bit = 0 if b == '0' else 1
        if bit == change_char:
            state = int(not state)
            return state
        else:
            return state

    def send(self, log_file_name, receiver_ip, port, init_state, change_char):
        """
        Generates, logs, and sends the binary message. Sets the sender's state
        to the initial state received from the config file if the sender state
        is unset.
        """
        if self.sender_state == None:
            self.sender_state = init_state
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for b in binary_message:
            bit = self.determine_sending(b, self.sender_state, change_char)
            packet = IP(dst=receiver_ip) / UDP(dport=port) / DNS(tc=bit)
            CovertChannelBase.send(self, packet)

    def stop_condition(self, packet):
        """
        Halts receiving messages if the receiver has received a '.' character.
        """
        return len(self.message) > 0 and self.message[-1] == '.'

    def determine_receiving(self, tc, state, change_char):
        """
        Determines which symbol is received based on its arguments.
        """
        def to_str(b): return "0" if b == 0 else "1"
        if tc == change_char:
            # if changing characted is encountered (which is 1 by default)
            # change state.
            state = int(not state)
        # return the state in both cases, its character equivalent
        return to_str(state)

    def packet_handler(self, packet, port, change_char):
        """
        Receives the appropriate packets and constructs the message using the
        bits it interprets. After receiving 8 bits, it converts the byte to its
        ASCII equivalent and appends to the constructed message.
        """
        if UDP in packet and packet[UDP].dport == port:
            tc = packet[DNS].tc
            self.bits += self.determine_receiving(tc, self.receiver_state, change_char)
            if len(self.bits) == 8:
                self.message += CovertChannelBase.convert_eight_bits_to_character(self, self.bits)
                # reset the bits every byte
                self.bits = ""

    def receive(self, log_file_name, port, init_state, change_char):
        """
        Receives and logs the binary message. Sets the receiver's state to the
        initial state received from the config file if the receiver state is
        unset.
        """
        if self.receiver_state == None:
            self.receiver_state = init_state
        # TODO: prn is unreadable lambda slop, simplify
        sniff(iface="eth0", prn=(lambda p: self.packet_handler(p, port, change_char)), stop_filter=self.stop_condition, filter=f"udp port {port}")
        self.log_message(self.message, log_file_name)
