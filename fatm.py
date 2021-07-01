#!/usr/bin/python3

from src.Fuzz_Sequence import *
import logging
import threading
import time
import sys
from src.Fuzz_Connect import *
from Pkt_Configurer import *
import os, argparse
from argparse import RawTextHelpFormatter

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
	if not os.path.exists('logs'):
		os.makedirs('logs')

	args = parse_args()

	input_list = open(args.input).read().splitlines()
	dst = args.target.split(':')[0]
	dport = int(args.target.split(':')[1])

	print_banner()
	print(f"[+] Target: {dst}:{dport}")

	try:
		seq = Fuzz_Sequence(dst, dport)
	except:
		print("[!] Error connecting to target. Exiting.")
		sys.exit(1)


	if args.sequence:
		run_sequences(args.packettypes, input_list, seq)

	elif args.template:
		fuzz_templates(seq)

	else:
		# guided mode
		print("(1) Fuzzing Sequences (2) Fuzzing Templates")
		fuzz_type = str(input())

		if fuzz_type == "1":
			print("Choose Packet Types:\n(1) CONNECT, (2) CONNACK, (3) PUBLISH, (4) PUBACK,\n(5) PUBREC,  (6) PUBREL,  (7) PUBCOMP, (8) SUBSCRIBE")
			seq_nums = str(input())
			list(seq_nums)
			print(seq_nums)
			run_sequences(seq_nums, input_list, seq)

		if fuzz_type == "2":
			fuzz_templates(seq)

		# secret mode for memory leak
		if fuzz_type == "3":
			seq.will_prop_sequence()
					
def fuzz_templates(seq):
	"starts the packet configurer that sends by defined template"
	print("Choose Packet Types:\n(1) CONNECT, (2) CONNACK, (3) PUBLISH, (4) PUBACK,\n(5) PUBREC,  (6) PUBREL,  (7) PUBCOMP, (8) SUBSCRIBE")
	configurer = Pkt_Configurer(seq)	
	while True:
		pkt_type = str(input()) # TODO
		if pkt_type == "exit":
			main()
		elif pkt_type == "1":
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
	"starts the fuzzing functionality for the given control packet types and input list"
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

def show_usage(help):
	print_banner()
	print(help)

def parse_args():
	"parses command line arguments"
	parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)

	group = parser.add_argument_group('mode selection')
	group_ex = group.add_mutually_exclusive_group()
	group_ex.add_argument("--guided", action='store_true', default=True, help="Guided fuzzing mode (default)")
	group_ex.add_argument("--sequence", action='store_true', default=False, help="Sequential fuzzing mode")
	group_ex.add_argument("--template", action='store_true', default=False, help="Template fuzzing mode")

	opts = parser.add_argument_group('options')
	opts.add_argument('-i', '--input', type=str, help='File with list of fuzzing inputs, separated by newlines (default: ./input/input.txt)',
						default="./input/input.txt", required=False)
	opts.add_argument('-t', '--target', type=str,
						help='Target IP and Port of the broker to fuzz, separated by a colon (e.g. 192.168.2.1:1800)',
						required=True)
	opts.add_argument('-p', '--packettypes', type=str, help= \
		"""Packet types, e.g. for types 1,2,3 and 6, enter 1236. Available types are:
(1) CONNECT, (2) CONNACK, (3) PUBLISH, (4) PUBACK,
(5) PUBREC,  (6) PUBREL,  (7) PUBCOMP, (8) SUBSCRIBE""")

	parser.usage = show_usage(parser.format_help())  # show help on error

	args = parser.parse_args()
	if (args.sequence or args.template) and args.packettypes is None:
		parser.error("Sequenced fuzzing and Template mode requires -p | --packettypes")

	return args

if __name__ == "__main__":
	main()
