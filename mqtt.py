# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>
# This program is published under GPLv2 license

# scapy.contrib.description = Message Queuing Telemetry Transport (MQTT)
# scapy.contrib.status = loads

# This file was extended to support the use of properties as defined in
# the MQTT standard. Additionaly, some existing classes were modified to 
# meet the requirements defined in the MQTT standard.
# All changes have been made visible as a comment above the class definition.


from scapy.packet import Packet, bind_layers
from scapy.fields import FieldLenField, BitEnumField, StrLenField, \
    ShortField, ConditionalField, ByteEnumField, ByteField, PacketListField, IntField
from scapy.all import Padding, PacketField
from scapy.layers.inet import TCP
from scapy.error import Scapy_Exception
from scapy.compat import orb, chb
from scapy.volatile import RandNum
from scapy.config import conf


# CUSTOM FIELDS
# source: http://stackoverflow.com/a/43717630
class VariableFieldLenField(FieldLenField):
    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        data = []
        while val:
            if val > 127:
                data.append(val & 127)
                val //= 128
            else:
                data.append(val)
                lastoffset = len(data) - 1
                data = b"".join(chb(val | (0 if i == lastoffset else 128))
                                for i, val in enumerate(data))
                return s + data
            if len(data) > 3:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)
        # If val is None / 0
        return s + b"\x00"

    def getfield(self, pkt, s):
        value = 0
        for offset, curbyte in enumerate(s):
            curbyte = orb(curbyte)
            value += (curbyte & 127) * (128 ** offset)
            if curbyte & 128 == 0:
                return s[offset + 1:], value
            if offset > 2:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)

    def randval(self):
        return RandVariableFieldLen()


class RandVariableFieldLen(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 268435455)


# LAYERS
CONTROL_PACKET_TYPE = {
    1: 'CONNECT',
    2: 'CONNACK',
    3: 'PUBLISH',
    4: 'PUBACK',
    5: 'PUBREC',
    6: 'PUBREL',
    7: 'PUBCOMP',
    8: 'SUBSCRIBE',
    9: 'SUBACK',
    10: 'UNSUBSCRIBE',
    11: 'UNSUBACK',
    12: 'PINGREQ',
    13: 'PINGRESP',
    14: 'DISCONNECT',
    15: 'AUTH'  # Added in v5.0
}


QOS_LEVEL = {
    0: 'At most once delivery',
    1: 'At least once delivery',
    2: 'Exactly once delivery'
}


# source: http://stackoverflow.com/a/43722441
class MQTT(Packet):
    name = "MQTT fixed header"
    fields_desc = [
        BitEnumField("type", 1, 4, CONTROL_PACKET_TYPE),
        BitEnumField("DUP", 0, 1, {0: 'Disabled',
                                   1: 'Enabled'}),
        BitEnumField("QOS", 0, 2, QOS_LEVEL),
        BitEnumField("RETAIN", 0, 1, {0: 'Disabled',
                                      1: 'Enabled'}),
        # Since the size of the len field depends on the next layer, we need
        # to "cheat" with the length_of parameter and use adjust parameter to
        # calculate the value.
        VariableFieldLenField("len", None, length_of="len",
                              adjust=lambda pkt, x: len(pkt.payload),),
    ]


PROTOCOL_LEVEL = {
    3: 'v3.1',
    4: 'v3.1.1',
    5: 'v5.0'
}


# Added by Kathrin Kleinhammer on August 20, 2021
class MQTTConnectProperty(Packet):
	name = "MQTT connect property item"
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
bind_layers(MQTTConnectProperty, Padding)    


# Added by Kathrin Kleinhammer on August 20, 2021
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
bind_layers(MQTTWillProperty, Padding)


# Added by Kathrin Kleinhammer on August 20, 2021
class MQTTWill(Packet):
	name = "MQTT will"
	fields_desc = [
		VariableFieldLenField("len", None, length_of="len",
							  adjust=lambda pkt, x: sum( [len(x) for x in pkt.properties] ),),
		PacketListField("properties", [], cls=MQTTWillProperty),		
	]
	

# Modified by Kathrin Kleinhammer on August 20, 2021
# to support properties and will properties
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
        VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum([len(x) for x in pkt.properties]),),
        PacketListField("properties", [], cls=MQTTConnectProperty),
        FieldLenField("clientIdlen", None, length_of="clientId"),
        StrLenField("clientId", "",
                    length_from=lambda pkt: pkt.clientIdlen),
	    #ByteField("properties", 0),
        ConditionalField(PacketField("willproperties", None, cls=MQTTWill),
                         lambda pkt: pkt.willflag == 1),
        #Payload with optional fields depending on the flags
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
bind_layers(MQTTConnect, MQTTWill, {'willflag':True })	


RETURN_CODE = {
    0: 'Connection Accepted',
    1: 'Unacceptable protocol version',
    2: 'Identifier rejected',
    3: 'Server unavailable',
    4: 'Bad username/password',
    5: 'Not authorized'
}


# Added by Kathrin Kleinhammer on August 20, 2021
class MQTTConnackProperty(Packet):
	name = "MQTT Connack property item"
	fields_desc = [
		ByteEnumField("type", None, {
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
bind_layers(MQTTConnackProperty, Padding)


# Modified by Kathrin Kleinhammer on August 20, 2021 to support properties
class MQTTConnack(Packet):
    name = "MQTT connack"
    fields_desc = [
        ByteField("sessPresentFlag", 0),
        ByteEnumField("retcode", 0, RETURN_CODE),
		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum([len(x) for x in pkt.properties]),),
		PacketListField("properties", [], cls=MQTTConnackProperty),
        # this package has not payload
    ]


class MQTTTopic(Packet):
    name = "MQTT topic"
    fields_desc = [
        FieldLenField("length", None, length_of="topic"),
        StrLenField("topic", "", length_from=lambda pkt:pkt.length)
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer

bind_layers(MQTTTopic, Padding)


class MQTTTopicQOS(MQTTTopic):
    fields_desc = MQTTTopic.fields_desc + [ByteEnumField("QOS", 0, QOS_LEVEL)]
bind_layers(MQTTTopicQOS, Padding)


# Added by Kathrin Kleinhammer on August 20, 2021
class MQTTPublishProperty(Packet):
	name = "MQTT Publish property item"
	fields_desc = [
		ByteEnumField("type", None, {
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
		ConditionalField(VariableFieldLenField("sub_id", None), lambda pkt: pkt.type == 0x0B),
		
		ConditionalField(FieldLenField("content_type_len", None, length_of="content_type"),
						 lambda pkt: pkt.type == 0x03),
		ConditionalField(StrLenField("content_type", "",
									 length_from=lambda pkt: pkt.content_type_len),	lambda pkt: pkt.type == 0x03),	              
	]
bind_layers(MQTTPublishProperty, Padding)


# Added by Kathrin Kleinhammer on August 20, 2021
class MQTTSubscribeProperty(Packet):
	name = "MQTT Subscribe property item"
	fields_desc = [
		ByteEnumField("type", None, {
			0x0B:"SUBSCRIPTION_ID",
			0x26:"USER_PROPERTY"}),
		ConditionalField(VariableFieldLenField("sub_id", None), lambda pkt: pkt.type == 0x0B),
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
bind_layers(MQTTSubscribeProperty, Padding)


# Modified by Kathrin Kleinhammer on August 20, 2021 to support properties
class MQTTPublish(Packet):
	name = "MQTT publish"
	fields_desc = [
		FieldLenField("length", None, length_of="topic"),
		StrLenField("topic", "", length_from=lambda pkt: pkt.length),
		ConditionalField(ShortField("msgid", None),
						 lambda pkt: (pkt.underlayer.QOS == 1 or
									  pkt.underlayer.QOS == 2)),
		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum([len(x) for x in pkt.properties]),),
		PacketListField("properties", [], cls=MQTTPublishProperty),
		
		StrLenField("value", "",length_from=lambda pkt: (pkt.underlayer.len - pkt.length - 2)),
	]


# Modified by Kathrin Kleinhammer on August 20, 2021 
# to support properties and meet the requirements of the MQTT standard
class MQTTSubscribe(Packet):
	name = "MQTT subscribe"
	fields_desc = [
		ConditionalField(ShortField("msgid", None),
						 lambda pkt: (pkt.underlayer.QOS == 1 or
									  pkt.underlayer.QOS == 2)),
		VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum([len(x) for x in pkt.properties]),),
		PacketListField("properties", [], cls=MQTTSubscribeProperty),
		PacketListField("topics", [], cls=MQTTTopicQOS),
]


# Added by Kathrin Kleinhammer on August 20, 2021
class MQTTPubSubStatusProperty(Packet):
	name = "MQTT Puback, Pubrec, Pubrel, Pubcomp property item"
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
bind_layers(MQTTPubSubStatusProperty, Padding)


# Modified by Kathrin Kleinhammer on August 20, 2021 to support properties
class MQTTPuback(Packet):
    name = "MQTT puback"
    fields_desc = [
        ShortField("msgid", None),
        ByteField("reason_code", None),
        VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum([len(x) for x in pkt.properties]),),
		PacketListField("properties", [], cls=MQTTPubSubStatusProperty),
    ]


# Modified by Kathrin Kleinhammer on August 20, 2021 to support properties
class MQTTPubrec(Packet):
    name = "MQTT pubrec"
    fields_desc = [
        ShortField("msgid", None),
        ByteField("reason_code", None),
        VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum([len(x) for x in pkt.properties]),),
		PacketListField("properties", [], cls=MQTTPubSubStatusProperty),
    ]


# Modified by Kathrin Kleinhammer on August 20, 2021 to support properties
class MQTTPubrel(Packet):
    name = "MQTT pubrel"
    fields_desc = [
        ShortField("msgid", None),
        ByteField("reason_code", None),
        VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum([len(x) for x in pkt.properties]),),
		PacketListField("properties", [], cls=MQTTPubSubStatusProperty),
    ]


# Modified by Kathrin Kleinhammer on August 20, 2021 to support properties
class MQTTPubcomp(Packet):
    name = "MQTT pubcomp"
    fields_desc = [
        ShortField("msgid", None),
        ByteField("reason_code", None),
        VariableFieldLenField("len", None, length_of="len", adjust=lambda pkt, x: sum([len(x) for x in pkt.properties]),),
		PacketListField("properties", [], cls=MQTTPubSubStatusProperty),
    ]



ALLOWED_RETURN_CODE = {
    0: 'Success',
    1: 'Success',
    2: 'Success',
    128: 'Failure'
}


class MQTTSuback(Packet):
    name = "MQTT suback"
    fields_desc = [
        ShortField("msgid", None),
        ByteEnumField("retcode", None, ALLOWED_RETURN_CODE)
    ]


class MQTTUnsubscribe(Packet):
    name = "MQTT unsubscribe"
    fields_desc = [
        ShortField("msgid", None),
        PacketListField("topics", [], cls=MQTTTopic)
    ]


class MQTTUnsuback(Packet):
    name = "MQTT unsuback"
    fields_desc = [
        ShortField("msgid", None)
    ]


# Added by Kathrin Kleinhammer on August 20, 2021
DISCONNECT_REASON = {
    0x00: 'Normal disconnection',
    0x04: 'Disconnect with Will Message',
    0x80: 'Unspecified error',
    0x81: 'Malformed Packet',
    0x82: 'Protocol Error',
    0x83: 'Implementation specific error',
    0x87: 'Not authorized',
    0x89: 'Server busy',
    0x8B: 'Server shutting down',
    0x8D: 'Keep Alive timeout',
    0x8E: 'Session taken over',
    0x8F: 'Topic Filter invalid',
    0x90: 'Topic Name invalid',
    0x93: 'Receive Maximum exceeded',
    0x94: 'Topic Alias invalid',
    0x95: 'Packet too large',
    0x96: 'Message rate too high',
    0x97: 'Quota exceeded',
    0x98: 'Administrative action',
    0x99: 'Payload format invalid',
    0x9A: 'Retain not supported',
    0x9B: 'QoS not supported',
    0x9C: 'Use another server',
    0x9D: 'Server moved',
    0x9E: 'Shared Subscriptions not supported',
    0x9F: 'Connection rate exceeded',
    0xA0: 'Maximum connect time',
    0xA1: 'Subscription Identifiers not supported',
    0xA2: 'Wildcard Subscriptions not supported'
}


class MQTTDisconnect(Packet):
    name = "MQTT disconnect"
    fields_desc = [
        ByteEnumField("reason_code", None, DISCONNECT_REASON)
    ]


# LAYERS BINDINGS

bind_layers(TCP, MQTT, sport=1883)
bind_layers(TCP, MQTT, dport=1883)
bind_layers(MQTT, MQTTConnect, type=1)
bind_layers(MQTT, MQTTConnack, type=2)
bind_layers(MQTT, MQTTPublish, type=3)
bind_layers(MQTT, MQTTPuback, type=4)
bind_layers(MQTT, MQTTPubrec, type=5)
bind_layers(MQTT, MQTTPubrel, type=6)
bind_layers(MQTT, MQTTPubcomp, type=7)
bind_layers(MQTT, MQTTSubscribe, type=8)
bind_layers(MQTT, MQTTSuback, type=9)
bind_layers(MQTT, MQTTUnsubscribe, type=10)
bind_layers(MQTT, MQTTUnsuback, type=11)
bind_layers(MQTT, MQTTDisconnect, type=14)
bind_layers(MQTTConnect, MQTT)
bind_layers(MQTTConnack, MQTT)
bind_layers(MQTTPublish, MQTT)
bind_layers(MQTTPuback, MQTT)
bind_layers(MQTTPubrec, MQTT)
bind_layers(MQTTPubrel, MQTT)
bind_layers(MQTTPubcomp, MQTT)
bind_layers(MQTTSubscribe, MQTT)
bind_layers(MQTTSuback, MQTT)
bind_layers(MQTTUnsubscribe, MQTT)
bind_layers(MQTTUnsuback, MQTT)
bind_layers(MQTTDisconnect, MQTT)

