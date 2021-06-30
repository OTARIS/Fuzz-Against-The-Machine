#!/usr/bin/python3
from Fuzz_Sequence import *
import logging
import threading
import time
import sys
from Fuzz_Connect import *
from Pkt_Configurer import *
import os
                          
def main():
	if not os.path.exists('logs'):
		os.makedirs('logs')
		
	with open('config/config.yaml', "r") as stream:
			data = yaml.safe_load(stream)
	input_list = open(data["input_file"]).read().splitlines()
	dst = data["target_ip"]
	dport = data["target_port"]
	resend_file = data["resend_file"]

	try:
		seq = Fuzz_Sequence(dst, dport)
	except ConnectionRefusedError as e:
		print(e,"\nThe broker seems to be offline")
		input("Press Enter to continue...")
		main()	
	
	art = \
"""      ___           ___                         ___     
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
"""
	print(art, "\n")
	
	print("(1) Fuzzing Sequences (2) Fuzzing Templates (3) Resend Logfile")
	fuzz_type = str(input())
	
	if fuzz_type == "1":
		print("Choose Packet Types:\n(1) CONNECT, (2) CONNACK, (3) PUBLISH, (4) PUBACK,\n(5) PUBREC,  (6) PUBREL,  (7) PUBCOMP, (8) SUBSCRIBE")
		seq_nums = str(input())
		list(seq_nums)
		run_sequences(seq_nums, input_list, seq)
		
	if fuzz_type == "2":
		fuzz_templates(seq)

	if fuzz_type == "3":
		seq.read_log(resend_file)		
	
	# secret mode for memory leak
	if fuzz_type == "4":
		seq.will_prop_sequence()
		
				
def fuzz_templates(seq):
	"starts the packet configurer that sends by defined template"
	print("Choose Packet Types:\n(1) CONNECT, (2) CONNACK, (3) PUBLISH, (4) PUBACK,\n(5) PUBREC,  (6) PUBREL,  (7) PUBCOMP, (8) SUBSCRIBE")
	configurer = Pkt_Configurer(seq)	
	while True:
		pkt_type = str(input())
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
			seq.utils.connect_log.info("### Starting CONNECT Sequence###")						
			seq.connect_sequence(input_list[i])
		if "2" in seq_nums:
			seq.utils.connack_log.info("### Starting CONNACK Sequence ###")									
			seq.connack_sequence(input_list[i])
		if "3" in seq_nums:	
			seq.utils.publish_log.info("### Starting PUBLISH Sequence ###")
			seq.publish_sequence(input_list[i])
		if "8" in seq_nums:
			seq.utils.subscribe_log.info("### Starting SUBSCRIBE Sequence ###")
			seq.subscribe_sequence(input_list[i])
		if "4" in seq_nums:
			seq.utils.puback_log.info("### Starting PUBACK Sequence ###")
			seq.pub_sequence(input_list[i], "PUBACK")
		if "5" in seq_nums:	
			seq.utils.pubrec_log.info("### Starting PUBREC Sequence ###")
			seq.pub_sequence(input_list[i], "PUBREC")
		if "6" in seq_nums:		
			seq.utils.pubrel_log.info("### Starting PUBREL Sequence ###")
			seq.pub_sequence(input_list[i], "PUBREL")
		if "7" in seq_nums:		
			seq.utils.pubcomp_log.info("### Starting PUBCOMP Sequence ###")
			seq.pub_sequence(input_list[i], "PUBCOMP")   
			
if __name__ == "__main__":
	main()
