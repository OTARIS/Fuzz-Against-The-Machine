from scapy.contrib.mqtt import *
from scapy.all import *
from scapy_mqtt import  *
import yaml
from src.Fuzz_Sequence import *


class Pkt_Configurer:

	def __init__(self, seq):
		self.seq = seq

	def read_yaml(self, yml):
		"read yaml file and return dictionary"
		with open(yml, "r") as stream:
			return yaml.safe_load(stream)
				
	def conf_subscribe(self):
		"read SUBSCRIBE yaml file, generate packet from dictionary and send" 
		data = self.read_yaml("templates/subscribe.yaml")
		data["pkt"] = MQTT()/MQTTSubscribe()
		pkt = self.seq.subscribe.fuzz_subscribe(**data)		
		self.seq.stream_sock.send(Raw(pkt))

	def conf_connect(self):
		"read CONNECT yaml file, generate packet from dictionary and send"
		data = self.read_yaml("templates/connect.yaml")
		data["pkt"] = MQTT()/MQTTConnect()
		pkt = self.seq.connect.fuzz_connect(**data)		
		self.seq.stream_sock.sr1(Raw(pkt), verbose=0)
		
	def conf_connack(self):
		"read CONNACK yaml file, generate packet from dictionary and send"
		data = self.read_yaml("templates/connack.yaml")
		data["pkt"] = MQTT()/MQTTConnack()
		pkt = self.seq.connack.fuzz_connack(**data)		
		self.seq.stream_sock.send(Raw(pkt))	
		
	def conf_publish(self):
		"read PUBLISH yaml file, generate packet from dictionary and send"
		data = self.read_yaml("templates/publish.yaml")
		data["pkt"] = MQTT()/MQTTPublish()
		pkt = self.seq.publish.fuzz_publish(**data)		
		self.seq.stream_sock.send(Raw(pkt))
		
	def conf_pubsubstatus(self, pkt_type):
		"read PUBACK or PUBREC or PUBREL or PUBCOMP yaml file, generate packet from dictionary and send"
		data = self.read_yaml("templates/pub-sub-status.yaml")
		if pkt_type == 4:
			data["pkt"] = MQTT()/MQTTPuback()
		if pkt_type == 5:
			data["pkt"] = MQTT()/MQTTPubrec()
		if pkt_type == 6:
			data["pkt"] = MQTT()/MQTTPubrel()
		if pkt_type == 7:
			data["pkt"] = MQTT()/MQTTPubcomp()			
		pkt = self.seq.publish.fuzz_pubstatus(**data)		
		self.seq.stream_sock.send(Raw(pkt))
						
