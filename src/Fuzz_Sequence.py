from scapy.contrib.mqtt import *
from scapy.all import *
import random
from scapy_mqtt import  *
from src.Fuzz_Connect import *
from src.Fuzz_Connack import *
from src.Fuzz_Publish import *
from src.Fuzz_Subscribe import *
from Utils import *
import logging
from itertools import *

class Fuzz_Sequence:
	def __init__(self, dst, dport):
		self.dst = dst
		self.dport = dport
		self.sock = socket.socket()
		self.sock.connect((dst, dport))
		self.stream_sock = StreamSocket(self.sock, Raw)

		self.connect = Fuzz_Connect()
		self.connack = Fuzz_Connack()
		self.publish = Fuzz_Publish()
		self.subscribe = Fuzz_Subscribe()
		self.utils = Utils(self.stream_sock, self.dst, self.dport, self.connect, self.connack, self.publish, self.subscribe)		
	
	
	def connect_sequence(self, fuzz_data):
		"CONNECT - Generates dictionaries(fieldname: datatype) of every possible param combination"
		print("[+] Starting CONNECT Sequence" + f" Sequence with Fuzz: {fuzz_data}")
		params = { 
			"clientId": str,
			"protoname": str,
			"willtopic": str  ,
			"willmsg": str  ,
			"username": str  , 
			"password": str, 
			"klive" : int  ,
			"sess_expiry": int,
			"rec_max": ShortField ,
			"max_pkt": int, 
			"top_alias": ShortField,
			"req_res_info": ByteField ,
			"req_prob_info": ByteField ,
			"willdelay": int,
			"resp_topic": str,
			"willexpire": int,
		}
		
		#Create list that contains lists with param combinations
		params_comb = list( [ { key : params[key] } for key in x] for x in self.utils.powerset(params))
		
		for element in params_comb:
			params_dict = {}
			
			for dictdata in element:
				params_dict.update(dictdata)
			
			self.utils.fuzz_by_param(params_dict, "CONNECT", fuzz_data)
		print(f"    CONNECT packets sent: {Utils.connect_count}")
		print(f"    Total packets sent: {Utils.pkt_count}")
		Utils.connect_count = 0	
	
	
	def connack_sequence(self, fuzz_data):
		"CONNACK - Generates dictionaries(fieldname: datatype) of every possible param combination"
		print("[+] Starting CONNACK Sequence" + f" Sequence with Fuzz: {fuzz_data}")
		params = {
			"sessexpiry": int,
			"rec_max": ShortField,
			"max_qos": ByteField,
			"retain_avail": ByteField,
			"max_pkt": int,
			"clientId": str,
			"top_alias": ShortField,
			"reason_string": str,
			"keyval": dict,
			"wild_sub": ByteField,
			"sub_id": ByteField,
			"shared_sub": ByteField,
			"server_klive": ShortField,
			"res_info": str,
			"server_ref": str,
		}
		
		#Create list that contains lists with param combinations
		params_comb = list( [ { key : params[key] } for key in x] for x in self.utils.powerset(params))
		
		for element in params_comb:
			params_dict = {}
			
			for dictdata in element:
				params_dict.update(dictdata)
			self.utils.fuzz_by_param(params_dict, "CONNACK", fuzz_data)	
		print(f"    CONNACK packets sent: {Utils.connack_count}")
		print(f"    Total packets sent: {Utils.pkt_count}")
		Utils.connack_count = 0	
	
		
	def pub_sequence(self, fuzz_data, pub_type):
		"PUBACK PUBREC PUBREL PUBCOMP - Generates dictionaries(fieldname: datatype) of every possible param combination"
		print("[+] Starting " + pub_type + f" Sequence with Fuzz: {fuzz_data}")
		params = {
			"msgid": ShortField ,
			"reason_code": ByteField,
			"reason_string": str,
			"keyval": dict,
		}
		
		#Create list that contains lists with param combinations
		params_comb = list( [ { key : params[key] } for key in x] for x in self.utils.powerset(params))
		
		for element in params_comb:
			params_dict = {}
			
			for dictdata in element:
				params_dict.update(dictdata)
			self.utils.fuzz_by_param(params_dict, pub_type, fuzz_data)
		if pub_type == "PUBACK":
			print(f"     PUBACK packets sent: {Utils.puback_count}")
			Utils.puback_count = 0
		if pub_type == "PUBREC":
			print(f"    PUBREC packets sent: {Utils.pubrec_count}")
			Utils.pubrec_count = 0
		if pub_type == "PUBREL":
			print(f"    PUBREL packets sent: {Utils.pubrel_count}")
			Utils.pubrel_count = 0
		if pub_type == "PUBCOMP":
			print(f"    PUBCOMP packets sent: {Utils.pubcomp_count}")
			Utils.pubcomp_count = 0
		print(f"    Total packets sent: {Utils.pkt_count}")

		
	def publish_sequence(self, fuzz_data):
		"PUBLISH -  - Generates dictionaries(fieldname: datatype) of every possible param combination"
		print("[+] Starting PUBLISH Sequence" + f" Sequence with Fuzz: {fuzz_data}")
		publish_param = { 
			"topic": str,
			"value": str,
			"messexpiry": int  ,
			"topalias": int  ,
			"resp_topic": str  , 
			"keyval":dict, 
			"content_type" : str  ,
		}
		
		#Create list that contains lists with param combinations		
		params_comb = list( [ { key : publish_param[key] } for key in x] for x in self.utils.powerset(publish_param))
		
		for element in params_comb:
			params_dict = {}
			for dictdata in element:
				params_dict.update(dictdata)
			self.utils.fuzz_by_param(params_dict, "PUBLISH", fuzz_data)
		print(f"    PUBLISH packets sent: {Utils.publish_count}")
		print(f"    Total packets sent: {Utils.pkt_count}")
		Utils.publish_count = 0			
	
	
	def subscribe_sequence(self, fuzz_data):
		"SUBSCRIBE - Generates dictionaries(fieldname: datatype) of every possible param combination"
		print("[+] Starting SUBSCRIBE Sequence" + f" Sequence with Fuzz: {fuzz_data}")
		params = { 
			"msgid": int,
			"topics": str,
			"keyval":dict, 
		}

		#Create list that contains lists with param combinations		
		params_comb = list( [ { key : params[key] } for key in x] for x in self.utils.powerset(params))
		
		for element in params_comb:
			params_dict = {}			
			for dictdata in element:
				params_dict.update(dictdata)			
			self.utils.fuzz_by_param(params_dict, "SUBSCRIBE", fuzz_data)
		print(f"    SUBSCRIBE packets sent: {Utils.subscribe_count}")
		print(f"    Total packets sent: {Utils.pkt_count}")
	
	
	def check_broker_conn(self, runs):
		"calculates time between sending a packet and receiving the answer"
		res = 0
		f = open("con_log.txt", "a")
		for i in range(runs):
			sock = socket.socket()
			sock.connect((self.dst, self.dport))
			stream_sock = StreamSocket(sock, Raw)			
			pkt = self.connect.connect_std()
			a = stream_sock.sr1(pkt, verbose=False)
			delay = a.time - pkt.sent_time
			res += delay
			f.write("\nsend receive delay: " + str(delay*1000))
		res = (res/runs)*1000
		f.write("\nsend receive delay average: " + str(res))
		f.close()

	def will_prop_sequence(self):
		"send method for the discovered memory leak vulneralbility" 
		sock = socket.socket()
		sock.connect((self.dst, self.dport))
		stream_sock = StreamSocket(sock, Raw)
		pkt = self.connect.fuzz_will_properties_pkt()
		x = stream_sock.send(Raw(pkt))
