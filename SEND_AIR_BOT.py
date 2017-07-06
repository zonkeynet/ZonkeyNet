#!/usr/bin/env python3
"""
AirBot TX - bridge between your preferred IRC to the Airchat/ZonkeyNet radio users
by (valexxx@autistici.org)
Send messages from IRC to radio
"""
################################################################### 
# Code from project: ZonkeyNet (Mesh Radio Networks)
###################################################################

import socket
import requests
import time


nick = "airbotTX"
network = "127.0.0.1" # Your favorite IRC
port = 6667
irc = socket.socket()
handle = irc.makefile(mode = "rw", buffering = 1, encoding = "utf-8", newline = "\r\n")

chan = "#zonkeynet" # Your Chan
irc.connect((network, port))

print("PASS *", file = handle)
print("NICK " + nick, file = handle)
print("USER AirBot_TX 0 * :Your Name", file = handle) 


flag1 = True

for line in handle:
    line = line.strip()
    print(line.encode("utf-8", "replace"))
    if line[:4] == "PING":
        print("PONG :" + line.split(":")[1], file = handle)
        if flag1 == True:
            print("JOIN " + chan, file = handle)
            flag1 = False
    elif "PRIVMSG" in line:
        msg = ":".join(line.split(":")[2:])
        #if msg.startswith("!radio"):  # send only with !radio msgs
        if msg.startswith("!"): # use ! in front of msgs in order to remove the receive confirmation loop of msgs
         continue        
        sender = line.split("!")[0].replace(":", "")
        #Send to Radio via local WebServer 
        r = requests.post('http://localhost:8080', data={"postfield":sender + ": " + msg})
        time.sleep(10)  # Wait 10 seconds to send via radio mode PSK500R - 4 for mode PSK1000R
