# Copyright (C) OTARIS INTERACTIVE SERVICES GmbH
# Author: Kathrin Kleinhammer <kleinhammer@otaris.de>
# This program is published under GPLv2 license

from mqtt import MQTT, MQTTPublish, MQTTPublishProperty, MQTTPubSubStatusProperty

class Fuzz_Publish:
            
    def fuzz_pubstatus(self, msgid=0, reason_code=0, reason_string=None, user_property={"key":None, "value":None}, pkt=None):
        "generate custom PUBACK or PUBREC or PUBREL or PUBCOMP packet"
        pkt.msgid= msgid
        pkt.reason_code = reason_code 
        if reason_string is not None:
            pkt.properties.append(MQTTPubSubStatusProperty(type=0x1F, reason_string=reason_string))
        if "key" in user_property and "value" in user_property and user_property['key'] is not None and user_property['value'] is not None:
            pkt.properties.append(MQTTPubSubStatusProperty(type=0x26, key=user_property['key'] , value=user_property['value']))      
        return pkt  
    
    def fuzz_publish(self, topic=None, value=None, qos=0, messexpiry=None, topalias=None, resp_topic=None, user_property={"key":None, "value":None}, content_type=None, pkt = None):
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
            
        if "key" in user_property and "value" in user_property and user_property['key'] is not None and user_property['value'] is not None:
            pkt.properties.append(MQTTPublishProperty(type=0x26, key=user_property['key'] , value=user_property['value']))
        if content_type is not None:
            pkt.properties.append(MQTTPublishProperty(type=0x03, content_type=content_type))
        return pkt
        
        
        
        
        
        
