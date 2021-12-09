# Copyright (C) OTARIS INTERACTIVE SERVICES GmbH
# Author: Kathrin Kleinhammer <kleinhammer@otaris.de>
# This program is published under GPLv2 license

"""
This script is responsible for reading the provided arguments
and starting the Fuzzer.
"""

from sys import exit
from os.path import exists
from os import makedirs
from argparse import ArgumentParser
from argparse import RawTextHelpFormatter
from src.Fuzz_Sequence import Fuzz_Sequence
from Pkt_Configurer import Pkt_Configurer

def print_banner():
    print("""\
     ___           ___                         ___     
    /\__\         /\  \                       /\  \    
   /:/ _/_       /::\  \         ___         |::\  \   
  /:/ /\__\     /:/\:\  \       /\__\        |:|:\  \  
 /:/ /:/  /    /:/ /::\  \     /:/  /      __|:|\:\  \ 
/:/_/:/  /    /:/_/:/\:\__\   /:/__/      /::::|_\:\__\\
\:\/:/  /     \:\/:/  \/__/  /::\  \      \:\~~\  \/__/
 \::/__/       \::/__/      /:/\:\  \      \:\  \      
  \:\  \        \:\  \      \/__\:\  \      \:\  \     
   \:\__\        \:\__\          \:\__\      \:\__\    
    \/__/         \/__/           \/__/       \/__/    
     Fuzz        Against           The       Machine
""")


def main():
    print_banner()
    args = parse_args()

    if not exists('logs'):
        makedirs('logs')

    input_list = open(args.input).read().splitlines()

    # parse host and port
    try:
        dst = args.target.split(':')[0]
        dport = int(args.target.split(':')[1])
        print(f"[i] Target: {dst}:{dport}")
    except:
        print("[!] Target must be specified like <HOST>:<PORT>")
        exit(1)

    # try connecting to target
    try:
        seq = Fuzz_Sequence(dst, dport)
    except:
        print("[!] Error connecting to target. Exiting.")
        exit(1)

    # Mode selection
    if args.sequence:
        run_sequences(args.packettypes, input_list, seq)
    elif args.template:
        for pkt_type in [p for p in args.packettypes]:
            # reinitialize socket connection
            seq = Fuzz_Sequence(dst, dport)
            print(f"[+] Sending packet of type {pkt_type}")
            fuzz_templates(seq, args.packettypes)
    elif args.resend:
        seq.read_log(args.logfile)
    else: # guided mode
        print("(1) Fuzzing Sequences (2) Fuzzing Templates")
        fuzz_type = str(input())
        if fuzz_type == "1":
            print("""Choose Packet Types:
    (1) CONNECT, (2) CONNACK, (3) PUBLISH, (4) PUBACK,
    (5) PUBREC,  (6) PUBREL,  (7) PUBCOMP, (8) SUBSCRIBE""")
            seq_nums = str(input())
            run_sequences(seq_nums, input_list, seq)
        if fuzz_type == "2":
            while True:
                print("""Choose Packet Types:
    (1) CONNECT, (2) CONNACK, (3) PUBLISH, (4) PUBACK,
    (5) PUBREC,  (6) PUBREL,  (7) PUBCOMP, (8) SUBSCRIBE""")
                for pkt_type in [p for p in str(input())]:
                    # reinitialize socket connection
                    seq = Fuzz_Sequence(dst, dport)
                    print(f"[+] Sending packet of type {pkt_type}")
                    fuzz_templates(seq, pkt_type)
        if fuzz_type == "3": #  secret mode for memory leak
            seq.will_prop_sequence()


def fuzz_templates(seq, pkt_type):
    """starts the packet configurer that sends by defined template"""
    configurer = Pkt_Configurer(seq)
    if pkt_type == "1":
        configurer.conf_connect()
    elif pkt_type == "2":
        configurer.conf_connack()
    elif pkt_type == "3":
        configurer.conf_publish()
    elif pkt_type == "4":
        configurer.conf_pubsubstatus(4)
    elif pkt_type == "5":
        configurer.conf_pubsubstatus(5)
    elif pkt_type == "6":
        configurer.conf_pubsubstatus(6)
    elif pkt_type == "7":
        configurer.conf_pubsubstatus(7)
    elif pkt_type == "8":
        configurer.conf_subscribe()


def run_sequences(seq_nums, input_list, seq):
    """
    starts the fuzzing functionality for the given control packet types
    and input list
    """
    for i in range(len(input_list)):
        if "1" in seq_nums:
            seq.utils.connect_log.info("[+] Starting CONNECT Sequence")
            seq.connect_sequence(input_list[i])
        if "2" in seq_nums:
            seq.utils.connack_log.info("[+] Starting CONNACK Sequence")
            seq.connack_sequence(input_list[i])
        if "3" in seq_nums:
            seq.utils.publish_log.info("[+] Starting PUBLISH Sequence")
            seq.publish_sequence(input_list[i])
        if "8" in seq_nums:
            seq.utils.subscribe_log.info("[+] Starting SUBSCRIBE Sequence")
            seq.subscribe_sequence(input_list[i])
        if "4" in seq_nums:
            seq.utils.puback_log.info("[+] Starting PUBACK Sequence")
            seq.pub_sequence(input_list[i], "PUBACK")
        if "5" in seq_nums:
            seq.utils.pubrec_log.info("[+] Starting PUBREC Sequence")
            seq.pub_sequence(input_list[i], "PUBREC")
        if "6" in seq_nums:
            seq.utils.pubrel_log.info("[+] Starting PUBREL Sequence")
            seq.pub_sequence(input_list[i], "PUBREL")
        if "7" in seq_nums:
            seq.utils.pubcomp_log.info("[+] Starting PUBCOMP Sequence")
            seq.pub_sequence(input_list[i], "PUBCOMP")


def parse_args():
    """parses command line arguments"""
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)

    group = parser.add_argument_group('mode selection')
    group_ex = group.add_mutually_exclusive_group()
    group_ex.add_argument("--guided", action='store_true', default=True, help="Guided fuzzing mode (default)")
    group_ex.add_argument("--sequence", action='store_true', default=False, help="Sequential fuzzing mode")
    group_ex.add_argument("--template", action='store_true', default=False, help="Template fuzzing mode")
    group_ex.add_argument("--resend", action='store_true', default=False, help="Resend logfile")

    opts = parser.add_argument_group('options')
    opts.add_argument('-i', '--input', type=str, help='File with list of fuzzing inputs, separated by newlines (default: ./input/input.txt)',
                      default="./input/input.txt", required=False)
    opts.add_argument('-t', '--target', type=str,
                      help='Target IP and Port of the broker to fuzz, separated by a colon (e.g. 192.168.2.1:1883)',
                      required=True)
    opts.add_argument('-p', '--packettypes', type=str, help= \
        """Packet types, e.g. for types 1,2,3 and 6, enter 1236. Available types are:
(1) CONNECT, (2) CONNACK, (3) PUBLISH, (4) PUBACK,
(5) PUBREC,  (6) PUBREL,  (7) PUBCOMP, (8) SUBSCRIBE""")

    opts.add_argument('-l', '--logfile', type=str, help='Logfile to be resent (default: ./logs/connect.log)',
                      default="./logs/connect.log", required=False)

    parser.usage = parser.format_help() # show help on error

    args = parser.parse_args()
    if (args.sequence or args.template) and args.packettypes is None:
        parser.error("Sequenced fuzzing and Template mode requires -p | --packettypes")
    if args.resend and args.logfile is None:
        parser.error("Resend mode requires -l | --logfile")

    return args

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[!] Exiting")
        exit(1)
