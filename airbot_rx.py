
#!/usr/bin/env python
################################################################### 
# Code from project: ZonkeyNet Mesh Radio Network
###################################################################

import irc.client
import json
import logging
import time
from jaraco.stream import buffer
import collections
import thread

NEW_MSGS_ONLY = True

channel_name = "#ZonkeyNet"
log_file_path = "/home/pi/ZonkeyNet/.AirChatLog.json"
IRC_server_address = "chat.freenode.net"
IRC_nickname = "airBOT_RX"

old_msgs = {}
f2 = open(log_file_path)
if NEW_MSGS_ONLY == True:
    log2 = json.load(f2)
    for key2 in log2:
        old_msgs[key2] = True

def endofmotd(con1,event1):
    server1.join(channel_name)
    thread.start_new_thread(send_all_logged_msgs,())
    #send_all_logged_msgs()

def send_all_logged_msgs():
    global old_msgs
    sent = {}
    while True:
        time.sleep(1)  # increase this number to make it less CPU intensive
        f1 = open(log_file_path)
        try:
            log1 = json.load(f1)
            log1_sorted = collections.OrderedDict(sorted(log1.items(), key=lambda t: t[1]["timestamp"]))
            #i=1
            for key1 in log1_sorted:
                #print log1[key1]["content"]
                if log1_sorted[key1]["txrx"] == "rx":
                    msg_to_send_noR = log1_sorted[key1]["content"].replace("\r","")
                    msg_to_send_noRN = msg_to_send_noR.replace("\n","")
                    msg_to_send_noRN = msg_to_send_noRN[:480]
                    #if i not in sent:
                    if key1 not in sent and key1 not in old_msgs:
                        server1.privmsg(channel_name,msg_to_send_noRN)
                        log1.pop(key1)
                        #print log1[key1]["content"]
                        #sent[i] = True
                        sent[key1]=True
                        time.sleep(10)
                        #i += 1
        except Exception, e:
            print e
            continue
        
    
    
irc.client.ServerConnection.buffer_class = buffer.LenientDecodingLineBuffer

#logging.basicConfig(level=logging.DEBUG)  # commented out for debug
irc_client1 = irc.client.Reactor()
server1 = irc_client1.server()
server1.connect(IRC_server_address, 6667, IRC_nickname)

irc_client1.add_global_handler("endofmotd", endofmotd)

irc_client1.process_forever()
