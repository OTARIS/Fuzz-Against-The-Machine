import random
from scapy.all import *
from scapy.contrib.mqtt import *
import sys


class MQTTPingReq(Packet):
	name = "MQTT Ping-Request"
	fields_desc = [
		ByteField("len", 0),
	]


class MQTTConnackProperty(Packet):
	name = "MQTT Connack property item"
	fields_desc = [
		ByteEnumField("type", 2, {
			0x11:"SESSION_EXPIRY_INTERVAL",
			0x21:"RECEIVE_MAXIMUM",
			0x24:"MAXIMUM_QOS",
			0x25:"RETAIN_AVAILABLE",
			0x27:"MAXIMUM_PACKET_SIZE",
			0x12:"ASSIGNED_CLIENT_IDENTIFIER",
			0x22:"TOPIC_ALIAS_MAXIMUM",
			0x1F:"REASON_STRING",
			0x26:"USER_PROPERTY",
			0x28:"WILDCARD_SUB_AVAILABLE",
			0x29:"SUBSCRIPTION_ID_AVAILABLE",
			0x2A:"SHARED_SUB_AVAILABLE",
			0x13:"SERVER_KEEP_ALIVE",
			0x1A:"RESPONSE_INFORMATION",
			0x1C:"SERVER_REFERENCE",
			0x15:"AUTH_METHOD",
			0x16:"AUTH_DATA"}),
		ConditionalField(IntField("sessexpiry", None), lambda pkt: pkt.type == 0x11),
		ConditionalField(ShortField("rec_max", None), lambda pkt: pkt.type == 0x21),
		ConditionalField(ByteField("max_qos", None), lambda pkt: pkt.type == 0x24),
		ConditionalField(ByteField("retain_avail", None), lambda pkt: pkt.type == 0x25),
		ConditionalField(IntField("max_pkt", None), lambda pkt: pkt.type == 0x27),
		ConditionalField(FieldLenField("clientId_len", None, length_of="clientId"),
						 lambda pkt: pkt.type == 0x12),
		ConditionalField(StrLenField("clientId", "", length_from=lambda pkt: pkt.clientId_len),
						 lambda pkt: pkt.type == 0x12),                
		ConditionalField(ShortField("top_alias", None), lambda pkt: pkt.type == 0x22),        
		ConditionalField(FieldLenField("reason_string_len", None, length_of="reason_string"),
						 lambda pkt: pkt.type == 0x1F),
		ConditionalField(StrLenField("reason_string", "",
									 length_from=lambda pkt: pkt.reason_string_len),
						 lambda pkt: pkt.type == 0x1F),
		ConditionalField(FieldLenField("key_len", None, length_of="key"),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(StrLenField("key", "",
									 length_from=lambda pkt: pkt.key_len),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(FieldLenField("value_len", None, length_of="value"),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(StrLenField("value", "",
									 length_from=lambda pkt: pkt.value_len),
						 lambda pkt: pkt.type == 0x26),                                               
		ConditionalField(ByteField("wild_sub", None), lambda pkt: pkt.type == 0x28),
		ConditionalField(ByteField("sub_id", None), lambda pkt: pkt.type == 0x29),
		ConditionalField(ByteField("shared_sub", None), lambda pkt: pkt.type == 0x2A),
		ConditionalField(ShortField("server_klive", None), lambda pkt: pkt.type == 0x13),
		ConditionalField(FieldLenField("res_info_len", None, length_of="res_info"),
						 lambda pkt: pkt.type == 0x1A),
		ConditionalField(StrLenField("res_info", "", length_from=lambda pkt: pkt.res_info_len),						 
						 lambda pkt: pkt.type == 0x1A),                               
		ConditionalField(FieldLenField("server_ref_len", None, length_of="server_ref"),
						 lambda pkt: pkt.type == 0x1C),
		ConditionalField(StrLenField("server_ref", "", length_from=lambda pkt: pkt.server_ref_len),						 
						 lambda pkt: pkt.type == 0x1C),                
      
	]

class MQTTPubSubStatusProperty(Packet):
	name = "MQTT Puback property item"
	fields_desc = [
		ByteEnumField("type", None, {
			0x1F:"REASON_STRING",
			0x26:"USER_PROPERTY"}),
		ConditionalField(FieldLenField("reason_string_len", None, length_of="reason_string"),
						 lambda pkt: pkt.type == 0x1F),
		ConditionalField(StrLenField("reason_string", "",
									 length_from=lambda pkt: pkt.reason_string_len),
						 lambda pkt: pkt.type == 0x1F),                
		ConditionalField(FieldLenField("key_len", None, length_of="key"),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(StrLenField("key", "",
									 length_from=lambda pkt: pkt.key_len),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(FieldLenField("value_len", None, length_of="value"),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(StrLenField("value", "",
									 length_from=lambda pkt: pkt.value_len),
						 lambda pkt: pkt.type == 0x26),                                         
	]   

class MQTTPublishProperty(Packet):
	name = "MQTT Publish property item"
	fields_desc = [
		ByteEnumField("type", 3, {
			0x02:"MESSAGE_EXPIRY_INTERVAL",
			0x23:"TOPIC_ALIAS",
			0x08:"RESPONSE_TOPIC",
			0x26:"USER_PROPERTY",
			0x0B:"SUBSCRIPTION_ID",
			0x03:"CONTENT_TYPE"}),
		ConditionalField(IntField("messexpiry", None), lambda pkt: pkt.type == 0x02),
		ConditionalField(ShortField("topalias", None), lambda pkt: pkt.type == 0x23),        
		ConditionalField(FieldLenField("resp_topic_len", None, length_of="resp_topic"),
						 lambda pkt: pkt.type == 0x08),
		ConditionalField(StrLenField("resp_topic", "",
									 length_from=lambda pkt: pkt.resp_topic_len),
						 lambda pkt: pkt.type == 0x08), 
		ConditionalField(FieldLenField("key_len", None, length_of="key"),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(StrLenField("key", "",
									 length_from=lambda pkt: pkt.key_len),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(FieldLenField("value_len", None, length_of="value"),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(StrLenField("value", "",
									 length_from=lambda pkt: pkt.value_len),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(IntField("sub_id", None), lambda pkt: pkt.type == 0x0B),
		
		ConditionalField(FieldLenField("content_type_len", None, length_of="content_type"),
						 lambda pkt: pkt.type == 0x03),
		ConditionalField(StrLenField("content_type", "",
									 length_from=lambda pkt: pkt.content_type_len),	lambda pkt: pkt.type == 0x03),	              
	]   
		
class MQTTConnectProperty(Packet):
	name = "MQTT Connect property item"
	fields_desc = [
		ByteEnumField("type", 1, {
			0x11:"SESSION_EXPIRY_INTERVAL",
			0x21:"RECEIVE_MAXIMUM",
			0x27:"MAXIMUM_PACKET_SIZE",
			0x22:"TOPIC_ALIAS_MAXIMUN",
			0x19:"REQ_RESP_INFORMATION",
			0x17:"REQ_PROB_INFORMATION",
			0x26:"USER_PROPERTY",
			0x15:"AUTH_METHOD",
			0x16:"AUTH_DATA"}),
		ConditionalField(IntField("sess_expiry", None), lambda pkt: pkt.type == 0x11),
		ConditionalField(ShortField("rec_max", None), lambda pkt: pkt.type == 0x21),
		ConditionalField(IntField("max_pkt", None), lambda pkt: pkt.type == 0x27),
		ConditionalField(ShortField("top_alias", None), lambda pkt: pkt.type == 0x22),
		ConditionalField(ByteField("req_res_info", None), lambda pkt: pkt.type == 0x19),
		ConditionalField(ByteField("req_prob_info", None), lambda pkt: pkt.type == 0x17),

	]         


class MQTTSubscribeProperty(Packet):
	name = "MQTT Subscribe property item"
	fields_desc = [
		ByteEnumField("type", None, {
			0x0B:"SUBSCRIPTION_ID",
			0x26:"USER_PROPERTY"}),
		ConditionalField(IntField("sub_id", None), lambda pkt: pkt.type == 0x0B),
		ConditionalField(FieldLenField("key_len", None, length_of="key"),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(StrLenField("key", "",
									 length_from=lambda pkt: pkt.key_len),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(FieldLenField("value_len", None, length_of="value"),
						 lambda pkt: pkt.type == 0x26),
		ConditionalField(StrLenField("value", "",
									 length_from=lambda pkt: pkt.value_len),
						 lambda pkt: pkt.type == 0x26),                                         
	]	
class MQTTPuback(Packet):
	name = "MQTT puback"
	fields_desc = [
		ShortField("msgid", 0),
		ByteField("reason_code", None),
		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTPubSubStatusProperty),
		
	]

class MQTTPubrec(Packet):
	name = "MQTT pubrec"
	fields_desc = [
		ShortField("msgid", None),          
		ByteField("reason_code", None),
		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTPubSubStatusProperty),
		
	]


class MQTTPubrel(Packet):
	name = "MQTT pubrel"
	fields_desc = [
		ShortField("msgid", None),
		ByteField("reason_code", None),
		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTPubSubStatusProperty),        
	]


class MQTTPubcomp(Packet):
	name = "MQTT pubcomp"
	fields_desc = [
		ShortField("msgid", None),
		ByteField("reason_code", None),
		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTPubSubStatusProperty),        
	]

class MQTTSuback(Packet):
    name = "MQTT suback"
    fields_desc = [
        ShortField("msgid", None),
        VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTPubSubStatusProperty),
		ByteEnumField("retcode", None, ALLOWED_RETURN_CODE),
        
    ]


class MQTTConnack(Packet):
	name = "MQTT connack"
	fields_desc = [
		ByteField("sessPresentFlag", 0),
		ByteEnumField("retcode", 0, RETURN_CODE),
		VariableFieldLenField("len", None, length_of="len",
							  adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTConnackProperty),

		# this package has no payload
	]	

class MQTTWillProperty(Packet):
	name = "MQTT will property item"
	fields_desc = [
		ByteEnumField("type", 1, {
			0x18:"WILL_DELAY",			  
			0x02:"WILL_MSG_EXPIRY",
			0x03:"WILL_CONTENT_TYPE",
			0x08:"WILL_RESPONSE_TOPIC",
			0x09:"WILL_CORRELATION_DATA",
			0x26:"WILL_USER_PROPERTY"}),
		ConditionalField(IntField("willdelay", None), lambda pkt: pkt.type == 0x18),
		ConditionalField(IntField("willexpire", None), lambda pkt: pkt.type == 0x02),
		ConditionalField(FieldLenField("resp_topiclen", None, length_of="resp_topic"),
			lambda pkt: pkt.type == 0x08),
		ConditionalField(StrLenField("resp_topic", None,
			length_from=lambda pkt: pkt.resp_topiclen),
			lambda pkt: pkt.type == 0x08),
		]


class MQTTWill(Packet):
	name = "MQTT will"
	fields_desc = [
		VariableFieldLenField("len", None, length_of="len",
							  adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTWillProperty),		
	]


class MQTTConnect(Packet):
	name = "MQTT connect"
	fields_desc = [
		FieldLenField("length", None, length_of="protoname"),
		StrLenField("protoname", "",
					length_from=lambda pkt: pkt.length),
		ByteEnumField("protolevel", 5, PROTOCOL_LEVEL),
		BitEnumField("usernameflag", 0, 1, {0: 'Disabled',
											1: 'Enabled'}),
		BitEnumField("passwordflag", 0, 1, {0: 'Disabled',
											1: 'Enabled'}),
		BitEnumField("willretainflag", 0, 1, {0: 'Disabled',
											  1: 'Enabled'}),
		BitEnumField("willQOSflag", 0, 2, QOS_LEVEL),
		BitEnumField("willflag", 0, 1, {0: 'Disabled',
										1: 'Enabled'}),
		BitEnumField("cleansess", 0, 1, {0: 'Disabled',
										 1: 'Enabled'}),
		BitEnumField("reserved", 0, 1, {0: 'Disabled',
										1: 'Enabled'}),
		ShortField("klive", 0),

		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTConnectProperty),

		FieldLenField("clientIdlen", None, length_of="clientId"),
		StrLenField("clientId", "",
					length_from=lambda pkt: pkt.clientIdlen),
		ConditionalField(PacketField("willproperties", None, cls=MQTTWill),
						 lambda pkt: pkt.willflag == 1),
		# Payload with optional fields depending on the flags
		ConditionalField(FieldLenField("wtoplen", None, length_of="willtopic"),
						 lambda pkt: pkt.willflag == 1),
		ConditionalField(StrLenField("willtopic", "",
									 length_from=lambda pkt: pkt.wtoplen),
						 lambda pkt: pkt.willflag == 1),
		ConditionalField(FieldLenField("wmsglen", None, length_of="willmsg"),
						 lambda pkt: pkt.willflag == 1),
		ConditionalField(StrLenField("willmsg", "",
									 length_from=lambda pkt: pkt.wmsglen),
						 lambda pkt: pkt.willflag == 1),
		ConditionalField(FieldLenField("userlen", None, length_of="username"),
						 lambda pkt: pkt.usernameflag == 1),
		ConditionalField(StrLenField("username", "",
									 length_from=lambda pkt: pkt.userlen),
						 lambda pkt: pkt.usernameflag == 1),
		ConditionalField(FieldLenField("passlen", None, length_of="password"),
						 lambda pkt: pkt.passwordflag == 1),
		ConditionalField(StrLenField("password", "",
									 length_from=lambda pkt: pkt.passlen),
						 lambda pkt: pkt.passwordflag == 1),
	]


class MQTTPublish(Packet):
	name = "MQTT publish"
	fields_desc = [
		FieldLenField("length", None, length_of="topic"),
		StrLenField("topic", "",
					length_from=lambda pkt: pkt.length),
		ConditionalField(ShortField("msgid", None),
						 lambda pkt: (pkt.underlayer.QOS == 1 or
									  pkt.underlayer.QOS == 2)),
		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTPublishProperty),
		
		StrLenField("value", "",length_from=lambda pkt: (pkt.underlayer.len - pkt.length - 2)),
	]



class MQTTSubscribe(Packet):
	name = "MQTT subscribe"
	fields_desc = [
		ConditionalField(ShortField("msgid", None),
						 lambda pkt: (pkt.underlayer.QOS == 1 or
									  pkt.underlayer.QOS == 2)),
		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTSubscribeProperty),	
		FieldLenField("length", None, length_of="topics"),
		PacketListField("topics", [], cls=MQTTTopicQOS),
        ByteField("options", 0)
	
   ]

bind_layers(MQTT, MQTTPublish, type=3)
bind_layers(MQTTPublish, MQTT)

bind_layers(MQTT, MQTTConnack, type=2)
bind_layers(MQTTConnack, MQTT)

bind_layers(MQTT, MQTTPuback, type=4)
bind_layers(MQTTPuback, MQTT)

bind_layers(MQTT, MQTTPubrec, type=5)
bind_layers(MQTTPubrec, MQTT)

bind_layers(MQTT, MQTTPubrel, type=6)
bind_layers(MQTTPubrel, MQTT)

bind_layers(MQTT, MQTTPubcomp, type=7)
bind_layers(MQTTPubcomp, MQTT)

bind_layers(MQTT, MQTTSubscribe, type=8)
bind_layers(MQTTSubscribe, MQTT)

bind_layers(MQTT, MQTTSuback, type=9)
bind_layers(MQTTSuback, MQTT)

bind_layers(MQTT, MQTTPingReq, type=12)

bind_layers(MQTTConnect, MQTTWill, {'willflag':True })
