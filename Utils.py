from scapy.contrib.mqtt import *
from scapy.all import *
import random
from scapy_mqtt import  *
import logging
from itertools import *
import yaml

class Utils:
	pkt_count = 0
	connect_count = 0
	connack_count = 0	
	publish_count = 0
	subscribe_count = 0
	puback_count = 0
	pubrec_count = 0
	pubrel_count = 0
	pubcomp_count = 0
	
	
	def __init__(self, stream_sock, dst, dport, connect=None, connack=None, publish=None, subscribe=None):
		self.stream_sock = stream_sock
		self.dst = dst
		self.dport = dport
		self.formatter = logging.Formatter('%(asctime)s:%(message)s')	
		if connect is not None:
			self.connect = connect
		if connack is not None:
			self.connack = connack
		if publish is not None:
			self.publish = publish
		if subscribe is not None:	
			self.subscribe = subscribe
			
		self.connect_log = self.init_logger("connect_logger", "logs/connect.log")	
		self.connack_log = self.init_logger("connack_logger", "logs/connack.log")	
		self.publish_log = self.init_logger("publish_logger", "logs/publish.log")	
		self.puback_log = self.init_logger("puback_logger", "logs/puback.log")	
		self.pubrec_log = self.init_logger("pubrec_logger", "logs/pubrec.log")	
		self.pubrel_log = self.init_logger("pubrel_logger", "logs/pubrel.log")	
		self.pubcomp_log = self.init_logger("pubcomp_logger", "logs/pubcomp.log")	
		self.subscribe_log = self.init_logger("subscribe_logger", "logs/subscribe.log")	
	
	
	def init_socket(self, dst, dport):
		"initialize socket connection"
		self.sock = socket.socket()
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)	
		self.sock.connect((dst, dport))
		self.stream_sock = StreamSocket(self.sock, Raw)
	
	
	def init_logger(self, name, log_file, level=logging.DEBUG):
		"initialize a custom logger"
		handler = logging.FileHandler(log_file)        
		handler.setFormatter(self.formatter)

		logger = logging.getLogger(name)
		logger.setLevel(level)
		logger.addHandler(handler)
		return logger
	
	
	def powerset(self, iterable):
		"powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"		
		s = list(iterable)
		return chain.from_iterable(combinations(s, r) for r in range(len(s)+1))
	
	
	def fuzz_by_param(self, params, type_flag, fuzz_data):
		"main functionality to insert input data in the param combinations and send the packet"
		fuzz_number = random.randint(10,50000);
		fuzz_dict = {}
		if type_flag == "CONNECT":
			with open("templates/connect.yaml", "r") as stream:
				fuzz_dict = yaml.safe_load(stream)
			fuzz_dict["pkt"] = MQTT()/MQTTConnect()
		if type_flag == "CONNACK":
			fuzz_dict["pkt"] = MQTT()/MQTTConnack()
		if type_flag == "PUBLISH":
			with open("templates/publish.yaml", "r") as stream:
				fuzz_dict = yaml.safe_load(stream)			
			fuzz_dict["pkt"] = MQTT()/MQTTPublish()
		if type_flag == "SUBSCRIBE":
			with open("templates/subscribe.yaml", "r") as stream:
				fuzz_dict = yaml.safe_load(stream)
			fuzz_dict["pkt"] = MQTT()/MQTTSubscribe()
		if type_flag == "PUBACK":
			fuzz_dict["pkt"] = MQTT()/MQTTPuback()
		if type_flag == "PUBREC":
			fuzz_dict["pkt"] = MQTT()/MQTTPubrec()
		if type_flag == "PUBREL":
			fuzz_dict["pkt"] = MQTT()/MQTTPubrel()
		if type_flag == "PUBCOMP":
			fuzz_dict["pkt"] = MQTT()/MQTTPubcomp()			

		try:
			for fuzz_param, datatype in params.items() :
				if fuzz_param in fuzz_dict and fuzz_dict[fuzz_param] is not None:
					continue
				fuzz = fuzz_data
				
				if(datatype is ByteField):
					fuzz = random.randint(0,255)
				elif(datatype is ShortField):
					fuzz = random.randint(0,(2**16)-1)
					
				elif(datatype is int ):
					fuzz = fuzz_number
				
				elif datatype is dict:
					fuzz = {"key" : fuzz, "value": fuzz}
				elif type( fuzz ) is not datatype:
					print("incorrect datatype", type(fuzz) , "expected", datatype)
					continue
				fuzz_dict[fuzz_param] = fuzz;		
		except AttributeError as e:
			print("ERR:",e)
			pass
		if fuzz_data not in fuzz_dict.values() and "keyval" not in fuzz_dict.keys():
			type_flag = "NONE"	
		self.init_socket(self.dst, self.dport)	
		if type_flag == "PUBLISH":				
			self.stream_sock.sr1(Raw(MQTT()/MQTTConnect(clientId="client_"+str(random.randint(100,999)), protoname="MQTT")),timeout=0, verbose=0)
			self.send_pkt(self.publish.fuzz_publish(**fuzz_dict))
		if type_flag == "CONNECT":				
			self.send_pkt(self.connect.fuzz_connect(**fuzz_dict))
		if type_flag == "CONNACK":				
			self.stream_sock.sr1(Raw(MQTT()/MQTTConnect(clientId="client_"+str(random.randint(100,999)), protoname="MQTT")),timeout=0, verbose=0)
			self.send_pkt(self.connack.fuzz_connack(**fuzz_dict))
		if type_flag == "SUBSCRIBE":				
			self.stream_sock.sr1(Raw(MQTT()/MQTTConnect(clientId="client_"+str(random.randint(100,999)), protoname="MQTT")),timeout=0, verbose=0)
			self.send_pkt(self.subscribe.fuzz_subscribe(**fuzz_dict))
		if type_flag == "PUBACK" or type_flag == "PUBREC" or type_flag == "PUBREL" or type_flag == "PUBCOMP":				
			self.stream_sock.sr1(Raw(MQTT()/MQTTConnect(clientId="client_"+str(random.randint(100,999)), protoname="MQTT")),timeout=0, verbose=0)
			self.send_pkt(self.publish.fuzz_pubstatus(**fuzz_dict))						
		if self.stream_sock.fileno() != -1:
			self.finalize()

			
	def randomize_send(self,pkt, rate=0.2):
		"flip bytes randomly, control frequency by adjusting rate" 
		data = list(Raw(pkt).load)
		num = 0
		while num < len(data):
			if random.random() < rate:
				data[num] = random.randint(0,255);
			num = num + 1;
		return  data 
	
	
	def send_cut_pkt(self, pkt):
		"cut off one byte at the end of a packet and send until remaining length is 1"
		pkt = MQTT(pkt.build())
		for i in range(pkt.len+1,0,-1):
			time.sleep(0.001)
			self.init_socket(self.dst, self.dport)	
			cut = MQTT(pkt.build()[0:i])
			self.stream_sock.sr1(Raw(cut), timeout=0, verbose=0)
			Utils.pkt_count +=1
			if str(CONTROL_PACKET_TYPE[pkt.type]) == "CONNECT":
				Utils.connect_count += 1
				self.connect_log.info(chexdump(cut, dump=True))
			if str(CONTROL_PACKET_TYPE[pkt.type]) == "CONNACK":
				Utils.connack_count += 1
				self.connack_log.info(chexdump(cut, dump=True))
			if str(CONTROL_PACKET_TYPE[pkt.type]) == "SUBSCRIBE":
				Utils.subscribe_count += 1
				self.subscribe_log.info(chexdump(cut, dump=True))
			if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBLISH":
				Utils.publish_count += 1
				self.publish_log.info(chexdump(cut, dump=True))			
			if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBACK":
				Utils.puback_count += 1			
				self.puback_log.info(chexdump(cut, dump=True))
			if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBREC":
				Utils.pubrec_count += 1	
				self.pubrec_log.info(chexdump(cut, dump=True))		
			if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBREL":
				Utils.pubrel_count += 1
				self.pubrel_log.info(chexdump(cut, dump=True))			
			if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBCOMP":
				Utils.pubcomp_count += 1
				self.pubcomp_log.info(chexdump(cut, dump=True))
	
					
	def send_pkt(self, pkt):
		"main functionality to send, cut and flip bytes in a given packet"
		Utils.pkt_count+=2
		if str(CONTROL_PACKET_TYPE[pkt.type]) == "CONNECT":
			Utils.connect_count += 2
			logger = self.connect_log
		if str(CONTROL_PACKET_TYPE[pkt.type]) == "CONNACK":
			Utils.connack_count += 2
			logger = self.connack_log
		if str(CONTROL_PACKET_TYPE[pkt.type]) == "SUBSCRIBE":
			Utils.subscribe_count += 2
			logger = self.subscribe_log
		if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBLISH":
			Utils.publish_count += 2			
			logger = self.publish_log
		if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBACK":
			Utils.puback_count += 2
			logger = self.puback_log			
		if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBREC":
			Utils.pubrec_count += 2	
			logger = self.pubrec_log		
		if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBREL":
			Utils.pubrel_count += 2
			logger = self.pubrel_log			
		if str(CONTROL_PACKET_TYPE[pkt.type]) == "PUBCOMP":
			Utils.pubcomp_count += 2
			logger = self.pubcomp_log			
		try:
			logger.info(chexdump(pkt, dump=True))			
			x = self.stream_sock.sr1(Raw(pkt),timeout=0, verbose=0)
			self.send_cut_pkt(pkt)
			self.init_socket(self.dst, self.dport)
			rand = self.randomize_send(pkt)
			logger.info(chexdump(rand, dump=True) + "\n")
			self.stream_sock.send(Raw(rand))
		except (TypeError, struct.error) as err:
			print("FAIL", err, str(CONTROL_PACKET_TYPE[pkt.type]))
			print("FAIL PACKET:", pkt.build())
			pass	
		
	def finalize(self):
		"close socket connection"
		self.sock.shutdown(socket.SHUT_WR)
		self.sock.close()         
