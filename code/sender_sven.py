"""A Sender for the GBN protocol."""

# Disable pylint rules which are incompatible with our naming conventions
# pylint: disable=C0103,W0221,W0201,R0902,R0913,R0201

import argparse
import queue as que
import logging
from scapy.sendrecv import send
from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT

FORMAT = "[SENDER:%(lineno)3s - %(funcName)10s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

TIMEOUT = 1  # number of seconds before packets are retransmitted


class GBN(Packet):
    """The GBN Header.

    It includes the following fields:
        type: DATA or ACK
        options: sack support
        len: payload length
        hlen: header length
        num: sequence/ACK number
        win: sender/receiver window size
    """
    name = 'GBN'
    fields_desc = [BitEnumField("type", 0, 1, {0: "data", 1: "ack"}),
                   BitField("options", 0, 7),
                   ShortField("len", None),
                   ByteField("hlen", 0),
                   ByteField("num", 0),
                   ByteField("win", 0),
                   ConditionalField ( ByteField ("block_number", 0), lambda pkt:pkt.hlen > 6),
                   ConditionalField ( ByteField ("left_edge_1", 0), lambda pkt:pkt.hlen > 6),
                   ConditionalField ( ByteField ("length_1", 0), lambda pkt:pkt.hlen > 6),
                   ConditionalField ( ByteField ("padding_1", 0), lambda pkt:pkt.hlen > 9),
                   ConditionalField ( ByteField ("left_edge_2", 0), lambda pkt:pkt.hlen > 9),
                   ConditionalField ( ByteField ("length_2", 0), lambda pkt:pkt.hlen > 9),
                   ConditionalField ( ByteField ("padding_2", 0), lambda pkt:pkt.hlen > 12),
                   ConditionalField ( ByteField ("left_edge_3", 0), lambda pkt:pkt.hlen > 12),
                   ConditionalField ( ByteField ("length_3", 0), lambda pkt:pkt.hlen > 12)]


# GBN header is coming after the IP header
bind_layers(IP, GBN, frag=0, proto=222)


class GBNSender(Automaton):
    """Sender implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        win: Maximum window size of the sender
        n_bits: number of bits used to encode sequence number
        receiver: IP address of the receiver
        sender: IP address of the sender
        q: Queue for all payload messages
        buffer: buffer to save sent but not acknowledged segments
        current: Sequence number of next data packet to send
        unack: First unacked segment
        receiver_win: Current window advertised by receiver, initialized with
                      sender window size
        acks_received: dictonary of all acks_received key: ack, value: amount ack got received
        Q_4_2: Is Selective Repeat used?
        SACK: Is SACK used?
        Q_4_4: Is Congestion Control used?
    """

    def parse_args(self, sender, receiver, n_bits, payloads, win,
                   Q_4_2, Q_4_3, Q_4_4, **kwargs):
        """Initialize Automaton."""
        Automaton.parse_args(self, **kwargs)
        self.win = win
        self.n_bits = n_bits
        assert self.win < 2**self.n_bits
        self.receiver = receiver
        self.sender = sender
        self.q = que.Queue()
        for item in payloads:
            self.q.put(item)

        self.buffer = {}
        self.current = 0
        self.unack = 0
        self.receiver_win = win
        self.Q_4_2 = Q_4_2
        self.acks_received = {}
        self.SACK = Q_4_3
        self.Q_4_4 = Q_4_4

    def master_filter(self, pkt):
        """Filter packets of interest.

        Source has be the receiver and both IP and GBN headers are required.
        No ICMP packets.
        """
        return (IP in pkt and pkt[IP].src == self.receiver and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.SEND()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("All packets successfully transmitted!")

    @ATMT.state()
    def SEND(self):
        """Main state of sender.

        New packets are transmitted to the receiver as long as there is space
        in the window.
        """
        # check if you still can send new packets to the receiver
        if len(self.buffer) < min(self.win, self.receiver_win):
            try:
                # get next payload (automatically removes it from queue)
                payload = self.q.get(block=False)
                log.debug("Sending packet num: %s", self.current)

                # add the current segment to the buffer
                self.buffer[self.current] = payload
                log.debug("Current buffer size test: %s", len(self.buffer))

                ###############################################################
                # TODO:                                                       #
                # create a GBN header with the correct header field values    #
                # send a packet to the receiver containing the created header #
                # and the corresponding payload                               #
                ###############################################################
                if self.SACK != 1:
                    header_GBN = GBN(type = 0, options = 0, len=len(payload), hlen = 6, num = self.current, win = self.win)
                    send(IP(src=self.sender, dst=self.receiver)/header_GBN/self.buffer[self.current])

                if self.SACK == 1:
                    header_GBN = GBN(type = 0, options = 1, len=len(payload), hlen = 6, num = self.current, win = self.win)
                    send(IP(src=self.sender, dst=self.receiver)/header_GBN/self.buffer[self.current])                    

                # sequence number of next packet
                self.current = int((self.current + 1) % 2**self.n_bits)

                # back to the beginning of the state
                # (send next packet if possible)
                raise self.SEND()

            # no more payload pieces in the queue --> if all are acknowledged,
            # we can end the sender
            except que.Empty:
                if self.unack == self.current:
                    raise self.END()

    @ATMT.receive_condition(SEND)
    def packet_in(self, pkt):
        """Transition: Packet coming in from the receiver"""
        log.debug("Received packet: %s", pkt.getlayer(GBN).num)
        raise self.ACK_IN(pkt)

    @ATMT.state()
    def ACK_IN(self, pkt):
        """State for received ACK."""
        # check if type is ACK
        if pkt.getlayer(GBN).type == 0:
            log.error("Error: data type received instead of ACK %s", pkt)
            raise self.SEND()
        else:
            log.debug("Received ACK %s", pkt.getlayer(GBN).num)

            # set the receiver window size to the received value
            self.receiver_win = pkt.getlayer(GBN).win

            ack = pkt.getlayer(GBN).num

            ################################################################
            # TODO:                                                        #
            # remove all the acknowledged sequence numbers from the buffer #
            # make sure that you can handle a sequence number overflow     #
            ################################################################

            if self.Q_4_2 == 1:
                if ack in self.acks_received:
                    self.acks_received[ack] += 1
                    if self.acks_received[ack] > 2:
                        header_GBN = GBN(type=0, len=len(self.buffer[ack]), hlen=6, num=ack, win=self.win)
                        send(IP(src=self.sender, dst=self.receiver) / header_GBN / self.buffer[ack])
                        # add to self.buffer bc we just resent?
                        self.acks_received[ack] = 0
                else:
                    self.acks_received[ack] = 1
            
            while self.unack != ack:
                if self.unack in self.buffer:
                    self.buffer.pop(self.unack)
                    self.unack = (self.unack + 1) % 2**self.n_bits
            
            '''
            if self.SACK == 1:
                block_length = pkt.getlayer(GBN).block_number
                pointer = self.unack
                if block_length > 0:
                    pointer_1 = self.unack
                    for i in self.win:
                        if pointer_1 + i in self.buffer.keys():
                            header_GBN = GBN(type=0, len=len(self.buffer[pointer_1+i]), hlen=6, num=pointer_1+i, win=self.win)
                            send(IP(src=self.sender, dst=self.receiver) / header_GBN / self.buffer[pointer_1+i])
                            if pointer_1 + i == pkt.getlayer(GBN).left_edge_1:
                                break

                if block_length > 1:
                    pointer_2 = pkt.getlayer(GBN).left_edge_1 + pkt.getlayer(GBN).length_1
                    for i in self.buffer:
                        if pointer_2 + i in self.buffer.keys():
                            header_GBN = GBN(type=0, len=len(self.buffer[pointer_2+i]), hlen=6, num=pointer_2+i, win=self.win)
                            send(IP(src=self.sender, dst=self.receiver) / header_GBN / self.buffer[pointer_2+i]
                            if (pointer_2 + i) == pkt.getlayer(GBN).left_edge_2:
                                break

                if block_length > 2:
                    pointer_3 = pkt.getlayer(GBN).left_edge_2 + pkt.getlayer(GBN).length_2
                    for i in self.buffer:
                        if pointer_3 + i in self.buffer.keys():
                            header_GBN = GBN(type=0, len=len(self.buffer[pointer_3+i]), hlen=6, num=pointer_3+i, win=self.win)
                            send(IP(src=self.sender, dst=self.receiver) / header_GBN / self.buffer[pointer_3+i]
                            if pointer_3 + i == pkt.getlayer(GBN).left_edge_3:
                                break
                '''

        # back to SEND state
        raise self.SEND()

    @ATMT.timeout(SEND, TIMEOUT)
    def timeout_reached(self):
        """Transition: Timeout is reached for first unacknowledged packet."""
        log.debug("Timeout for sequence number %s", self.unack)
        raise self.RETRANSMIT()

    @ATMT.state()
    def RETRANSMIT(self):
        """State for retransmitting packets."""

        ##############################################
        # TODO:                                      #
        # retransmit all the unacknowledged packets  #
        # (all the packets currently in self.buffer) #
        ##############################################
        if self.SACK != 1:
            for k in self.buffer.keys():
                payload_len = len(self.buffer[k])
                header_GBN = GBN(type=0, options = 0, len = payload_len, hlen=6, num=k, win=self.win)
                send(IP(src = self.sender, dst = self.receiver)/header_GBN/self.buffer[k])
        
        if self.SACK == 1:
            for k in self.buffer.keys():
                payload_len = len(self.buffer[k])
                header_GBN = GBN(type=0, options = 1, len = payload_len, hlen=6, num=k, win=self.win)
                send(IP(src = self.sender, dst = self.receiver)/header_GBN/self.buffer[k])



        # back to SEND state
        raise self.SEND()


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN sender')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                             'number field')
    parser.add_argument('input_file', type=str,
                        help='Path to the input file')
    parser.add_argument('window_size', type=int,
                        help='The window size of the sender')
    parser.add_argument('Q_4_2', type=int,
                        help='Use Selective Repeat (question 4.2)')
    parser.add_argument('Q_4_3', type=int,
                        help='Use Selective Acknowledgments (question 4.3)')
    parser.add_argument('Q_4_4', type=int,
                        help='Use Congestion Control (question 4.4/Bonus)')
    parser.add_argument('--interface', type=str, help='(optional) '
                        'interface to listen on')

    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface

    bits = args.n_bits
    assert bits <= 8

    in_file = args.input_file
    # list for binary payload
    payload_to_send_bin = list()
    # chunk size of payload
    chunk_size = 2**6

    # fill payload list
    with open(in_file, "rb") as file_in:
        while True:
            chunk = file_in.read(chunk_size)
            if not chunk:
                break
            payload_to_send_bin.append(chunk)

    # initial setup of automaton
    GBN_sender = GBNSender(args.sender_IP, args.receiver_IP, bits,
                           payload_to_send_bin, args.window_size, args.Q_4_2,
                           args.Q_4_3, args.Q_4_4)

    # start automaton
    GBN_sender.run()
