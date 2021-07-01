from scapy.contrib.mqtt import *
from scapy.all import *
import random
from scapy_mqtt import *
import logging

class Fuzz_Publish:
			
	def fuzz_pubstatus(self, msgid=0, reason_code=0, reason_string=None, keyval={"key":None, "value":None}, pkt=None):
		"generate custom PUBACK or PUBREC or PUBREL or PUBCOMP packet"
		pkt.msgid= msgid
		pkt.reason_code = reason_code 
		if reason_string is not None:
			pkt.properties.append(MQTTPubSubStatusProperty(type=0x1F, reason_string=reason_string))
		if "key" in keyval and "value" in keyval and keyval['key'] is not None and keyval['value'] is not None:
			pkt.properties.append(MQTTPubSubStatusProperty(type=0x26, key=keyval['key'] , value=keyval['value'] ))		
		return pkt	
	
	def fuzz_publish(self, topic=None, value=None, qos=0, messexpiry=None, topalias=None, resp_topic=None, keyval={"key":None, "value":None}, content_type=None, pkt = None):
		"generate custom PUBLISH packet"
		pkt = MQTT()/MQTTPublish()
		if topic is not None:
			pkt.topic = topic
		if value is not None:
			pkt.value = value
		pkt.QOS = qos
		if messexpiry is not None:
			pkt.properties.append(MQTTPublishProperty(type=0x02, messexpiry=messexpiry))
		if topalias is not None:
			pkt.properties.append(MQTTPublishProperty(type=0x23, topalias=topalias))
		if resp_topic is not None:
			pkt.properties.append(MQTTPublishProperty(type=0x08, resp_topic=resp_topic))
			
		if "key" in keyval and "value" in keyval and keyval['key'] is not None and keyval['value'] is not None:
			pkt.properties.append(MQTTPublishProperty(type=0x26, key=keyval['key'] , value=keyval['value'] ))
		if content_type is not None:
			pkt.properties.append(MQTTPublishProperty(type=0x03, content_type=content_type))
		return pkt
		
		
		
		
		
		
