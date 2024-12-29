from CovertChannelBase import CovertChannelBase

from scapy.all import IP, UDP, DNS, sniff

class MyCovertChannel(CovertChannelBase):
    # TODO: explain this part. I implemented a state machine with two
    # states, 0 and 1. In config.json, the states start at 0 and if the
    # sender sends 1, the state changes and starts emitting 1. Similarly,
    # sending 1 in state 1 changes the state to 0 and start emitting 0.
    sender_state = None
    receiver_state = None
    bits = ""
    message = ""

    def __init__(self):
        pass

    def determine_sending(self, b, state, change_char):
        bit = 0 if b == '0' else 1
        if bit == change_char:
            state = int(not state)
            return state
        else:
            return state

    def send(self, log_file_name, receiver_ip, port, init_state, change_char):
        # TODO: write comments and explain
        if self.sender_state == None:
            self.sender_state = init_state
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for b in binary_message:
            bit = self.determine_sending(b, self.sender_state, change_char)
            packet = IP(dst=receiver_ip) / UDP(dport=port) / DNS(tc=bit)
            CovertChannelBase.send(self, packet)

    def stop_condition(self, packet):
        return len(self.message) > 0 and self.message[-1] == '.'

    def determine_receiving(self, tc, state, change_char):
        def to_str(b): return "0" if b == 0 else "1"
        if tc == change_char:
            # if changing characted is encountered (which is 1 by default)
            # change state.
            state = int(not state)
        # return the state in both cases, the text equivalent
        return to_str(state)

    def packet_handler(self, packet, port, change_char):
        if UDP in packet and packet[UDP].dport == port:
            tc = packet[DNS].tc
            self.bits += self.determine_receiving(tc, self.receiver_state, change_char)
            if len(self.bits) == 8:
                self.message += CovertChannelBase.convert_eight_bits_to_character(self, self.bits)
                # reset the bits every byte
                self.bits = ""

    def receive(self, log_file_name, port, init_state, change_char):
        # TODO: explain more
        if self.receiver_state == None:
            self.receiver_state = init_state
        # TODO: prn is unreadable lambda slop, simplify
        sniff(iface="eth0", prn=(lambda p: self.packet_handler(p, port, change_char)), stop_filter=self.stop_condition, filter=f"udp port {port}")
        self.log_message(self.message, log_file_name)
