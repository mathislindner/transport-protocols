"""A Receiver for the GBN protocol."""

# Disable pylint rules which are incompatible with our naming conventions
# pylint: disable=C0103,W0221,W0201,R0902,R0913,R0201


import os
import random
import logging
import argparse
from scapy.sendrecv import send
from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT
import queue as que

FORMAT = "   [RECEIVER:%(lineno)3s - %(funcName)12s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# fixed random seed to reproduce packet loss
random.seed('TEST')


class GBN(Packet):
    """The GBN Header.

    It includes the following fields:
        type: DATA or ACK
        options: sack support
        len: payload length
        hlen: header length
        num: sequence/ACK number
        win: sender/receiver window size
        block_length: indecates the how many additional blocks will be used
        left_edge_1: first ack of first sequence
        length_1:
        padding_1: --
        left_edge_2: first ack of second sequence
        length_2:
        padding_2: --
        left_edge_3: first ack of third sequence
        length_3:
    """
    name = 'GBN'
    fields_desc = [BitEnumField("type", 0, 1, {0: "data", 1: "ack"}),
                   BitField("options", 0, 7),
                   ShortField("len", None),
                   ByteField("hlen", 0),
                   ByteField("num", 0),
                   ByteField("win", 0),
                   ConditionalField ( ByteField ("block_length", 0), lambda pkt:pkt.options == 1),
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


class GBNReceiver(Automaton):
    """Receiver implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        win: Window size advertised by receiver
        n_bits: number of bits used to encode sequence number
        p_data: loss probability for data segments (0 <= p_data < 1)
        p_ack: loss probability for ACKs (0 <= p_ack < 1)
        sender: IP address of the sender
        receiver: IP address of the receiver
        next: Next expected sequence number
        out_file: Name of output file
        p_file: Expected payload size
        end_receiver: Can we close the receiver?
        end_num: Sequence number of last packet + 1
        buffer: buffer to save out of order segments
    """

    def parse_args(self, receiver, sender, nbits, out_file, window, p_data,
                   p_ack, chunk_size, **kargs):
        """Initialize the automaton."""
        Automaton.parse_args(self, **kargs)
        self.win = window
        self.n_bits = nbits
        assert self.win <= 2**self.n_bits
        self.p_data = p_data
        assert p_data >= 0 and p_data < 1
        self.p_ack = p_ack
        assert p_ack >= 0 and p_ack < 1
        self.sender = sender
        self.receiver = receiver
        self.next = 0
        self.out_file = out_file
        self.p_size = chunk_size
        self.end_receiver = False
        self.end_num = -1
        self.buffer = {}
        self.block_length = 0
        self.left_edge_1 = 0
        self.length_1 = 0
        self.padding_1 = 0
        self.left_edge_2 = 0
        self.length_2 = 0
        self.padding_2 = 0
        self.left_edge_3 = 0
        self.length_3 = 0
        self.block_buffer = []

    def master_filter(self, pkt):
        """Filter packets of interest.

        Source has be the sender and both IP and GBN headers are required.
        No ICMP packets.
        """
        return (IP in pkt and pkt[IP].src == self.sender and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.WAIT_SEGMENT()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("Receiver closed")

    @ATMT.state()
    def WAIT_SEGMENT(self):
        """Waiting state for new packets."""
        log.debug("Waiting for segment %s", self.next)

    @ATMT.receive_condition(WAIT_SEGMENT)
    def packet_in(self, pkt):
        """Transition: Packet is coming in from the sender."""
        raise self.DATA_IN(pkt)

    @ATMT.state()
    def DATA_IN(self, pkt):
        """State for incoming data."""
        num = pkt.getlayer(GBN).num
        payload = bytes(pkt.getlayer(GBN).payload)
        sack_support = pkt.getlayer(GBN).options

        # received segment was lost/corrupted in the network
        if random.random() < self.p_data:
            log.debug("Data segment lost: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      num,
                      pkt.getlayer(GBN).win)
            raise self.WAIT_SEGMENT()

        # segment was received correctly
        else:
            log.debug("Received: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      num,
                      pkt.getlayer(GBN).win)

            # check if segment is a data segment
            ptype = pkt.getlayer(GBN).type
            if ptype == 0:
                if(sack_support):
                    counter = 0
                    seq_length = 0
                    buffer_keys = self.buffer.keys()
                    buffer_keys.sort()
                    #for i in range("""insert max ACK number"""):
                    #    if i not in buffer_keys:
                    #        print('this ACK is misisng: ' + str(i))
                    last_key = buffer_keys[0]
                    for key in self.buffer.keys():
                        if key == buffer_keys[0]:
                            continue
                        if key != last_key + 1:
                            last_key = key
                            if counter == 0:
                                self.block_buffer[counter] = key
                            else:
                                self.block_buffer[counter] = seq_length
                                seq_length = 0
                                self.block_buffer[counter + 1] = key
                                counter += 1
                            counter += 1 
                        else: 
                            last_key = key
                            seq_length += 1

                    if len(self.block_buffer) == 2:
                        self.block_length = 1
                        self.left_edge_1 = self.block_buffer[0]
                        self.length_1 = self.block_buffer[1]
                    elif len(self.block_buffer) == 4:
                        self.block_length = 2
                        self.left_edge_1 = self.block_buffer[0]
                        self.length_1 = self.block_buffer[1]
                        self.left_edge_2 = self.block_buffer[2]
                        self.length_2 = self.block_buffer[3]
                    elif len(self.block_buffer) >= 6:
                        self.block_length = 3
                        self.left_edge_1 = self.block_buffer[0]
                        self.length_1 = self.block_buffer[1]
                        self.left_edge_2 = self.block_buffer[2]
                        self.length_2 = self.block_buffer[3]
                        self.left_edge_3 = self.block_buffer[4]
                        self.length_3 = self.block_buffer[5]

                    

                # check if last packet --> end receiver
                if len(payload) < self.p_size:
                    self.end_receiver = True
                    self.end_num = (num + 1) % 2**self.n_bits

                                # this is the segment with the expected sequence number
                if num == self.next:
                    log.debug("Packet has expected sequence number: %s", num)

                    # append payload (as binary data) to output file
                    with open(self.out_file, 'ab') as file:
                        file.write(payload)

                    log.debug("Delivered packet to upper layer: %s", num)

                    self.next = int((self.next + 1) % 2 ** self.n_bits)

                    while self.next in self.buffer.keys():
                        log.debug("Added %s to output-file",self.next)
                        with open(self.out_file, 'ab') as file:
                            file.write(self.buffer.pop(self.next))
                        self.next = int((self.next + 1) % 2 ** self.n_bits)

                # this was not the expected segment
                else:
                    self.buffer[num] = payload
                    log.debug("Out of sequence segment [num = %s] received. "
                              "Expected %s", num, self.next)

            else:
                # we received an ACK while we are supposed to receive only
                # data segments
                log.error("ERROR: Received ACK segment: %s", pkt.show())
                raise self.WAIT_SEGMENT()

            # send ACK back to sender
            if random.random() < self.p_ack:
                # the ACK will be lost, discard it
                log.debug("Lost ACK: %s", self.next)

            # the ACK will be received correctly
            else:
                if sack_support == 1 and self.block_length == 1:
                    header_GBN = GBN(type="ack",
                                 options=1,
                                 len=0,
                                 hlen=9,
                                 num=self.next,
                                 win=self.win,
                                 block_length=self.block_length,
                                 left_edge_1=self.left_edge_1,
                                 length_1=self.length_1)

                elif sack_support == 1 and self.block_length == 2:
                    header_GBN = GBN(type="ack",
                                 options=1,
                                 len=0,
                                 hlen=12,
                                 num=self.next,
                                 win=self.win,
                                 block_length = self.block_length,
                                 left_edge_1 = self.left_edge_1,
                                 length_1 = self.length_1,
                                 padding_1 = self.padding_1,
                                 left_edge_2 = self.left_edge_2,
                                 length_2 = self.length_2)

                elif sack_support == 1 and self.block_length == 3:
                    header_GBN = GBN(type="ack",
                                 options=1,
                                 len=0,
                                 hlen=18,
                                 num=self.next,
                                 win=self.win,
                                 block_length = self.block_length,
                                 left_edge_1 = self.left_edge_1,
                                 length_1 = self.length_1,
                                 padding_1 = self.padding_1,
                                 left_edge_2 = self.left_edge_2,
                                 length_2 = self.length_2,
                                 padding_2 = self.padding_2,
                                 left_edge_3 = self.left_edge_3,
                                 length_3 = self.length_3)

                else:
                    header_GBN = GBN(type="ack",
                                     options=0,
                                     len=0,
                                     hlen=6,
                                     num=self.next,
                                     win=self.win)

                log.debug("Sending ACK: %s", self.next)
                send(IP(src=self.receiver, dst=self.sender) / header_GBN,
                     verbose=0)

                # last packet received and all ACKs successfully transmitted
                # --> close receiver
                if self.end_receiver and self.end_num == self.next:
                    raise self.END()

            # transition to WAIT_SEGMENT to receive next segment
            raise self.WAIT_SEGMENT()


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN receiver')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                        'number field')
    parser.add_argument('output_file', type=str,
                        help='Path to the output file (data from sender is '
                        'stored in this file)')
    parser.add_argument('window_size', type=int,
                        help='The window size of the receiver')
    parser.add_argument('data_l', type=float,
                        help='The loss probability of a data segment '
                        '(between 0 and 1.0)')
    parser.add_argument('ack_l', type=float,
                        help='The loss probability of an ACK '
                        '(between 0 and 1.0)')
    parser.add_argument('--interface', type=str, help='(optional) '
                        'interface to listen on')

    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface

    output_file = args.output_file    # filename of output file
    size = 2**6                       # normal payload size
    bits = args.n_bits
    assert bits <= 8

    # delete previous output file (if it exists)
    if os.path.exists(output_file):
        os.remove(output_file)

    # initial setup of automaton
    GBN_receiver = GBNReceiver(args.receiver_IP, args.sender_IP, bits,
                               output_file, args.window_size, args.data_l,
                               args.ack_l, size)
    # start automaton
GBN_receiver.run()