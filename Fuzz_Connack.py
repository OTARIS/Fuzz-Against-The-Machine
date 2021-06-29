from scapy.contrib.mqtt import *
from scapy.all import *
import random
from scapy_mqtt import  *

class Fuzz_Connack:
   
	def fuzz_connack(self, sessexpiry=None, rec_max=None, max_qos=None, retain_avail=None, max_pkt=None, clientId=None, top_alias=None, reason_string=None, keyval={"key":None, "value":None}, wild_sub=None, sub_id=None, shared_sub=None, server_klive=None, res_info=None, server_ref=None, pkt=None):
		"generate custom CONNACK packet"
		pkt = MQTT()/MQTTConnack()
		if sessexpiry is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x11, sessexpiry=sessexpiry))
		if rec_max is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x21, rec_max=rec_max))
		if max_qos is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x24, max_qos=max_qos))
		if retain_avail is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x25, retain_avail=retain_avail))			
		if max_pkt is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x27, max_pkt=max_pkt))	
		if clientId is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x12, clientId=clientId))
		if top_alias is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x22, top_alias=top_alias))
		if reason_string is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x1F, reason_string=reason_string))
		if "key" in keyval and "value" in keyval and keyval['key'] is not None and keyval['value'] is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x26, key=keyval['key'] , value=keyval['value'] ))						
		if wild_sub is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x28, wild_sub=wild_sub))
		if sub_id is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x29, sub_id=sub_id))
		if shared_sub is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x2A, shared_sub=shared_sub))
		if server_klive is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x13, server_klive=server_klive))
		if res_info is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x1A, res_info=res_info))
		if server_ref is not None:
			pkt.properties.append(MQTTConnackProperty(type=0x1C, server_ref=server_ref))
		return pkt	
