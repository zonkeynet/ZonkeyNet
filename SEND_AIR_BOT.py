#!/usr/bin/env python3
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
#!/usr/bin/env python3
################################################################### 
# Code from project: ZonkeyNet (Mesh Radio Networks)
###################################################################

import socket
import requests
import time
import random

BOT_NICK = "airbotTX"
BOT_FULLNAME = "another crazy bot"

BOT_SERVER = "chat.freenode.net"
BOT_PORT = 6667

BOT_CHANNEL = "#ZonkeyNet"

irc = socket.socket()
handle = irc.makefile(mode = "rw", buffering = 1, encoding = "utf-8", newline = "\r\n")

irc.connect((BOT_SERVER, BOT_PORT))

print("PASS *", file = handle)
print("NICK " + BOT_NICK, file = handle)
print("USER AirBot_TX 0 * :" + BOT_FULLNAME, file = handle) 

flag1 = True

def split_line(data):
    sender = None
    cmd = None
    args = []
    if (data.startswith(":")):
        d = data[1:].split(" ", 15)
        sender = d[0]
        cmd = d[1]
        for n in range(2, len(d)):
            if d[n].startswith(":"):
                args.append(d[n][1:] + " " + " ".join(d[n+1:]))
                break
            else:
                args.append(d[n])
    else:
        d = data.split(" ", 15)
        cmd = d[0]
        for n in range(1, len(d)):
            if d[n].startswith(":"):
                args.append(d[n][1:] + " " + " ".join(d[n+1:]))
                break
            else:
                args.append(d[n])
    return (sender, cmd, args)

RPL_END_OF_MOTD = "376"
ERR_NOMOTD = "422"
ERR_NICKNAMEINUSE = "433"       
             
for line in handle:
    line = line.strip()
#    print(line.encode("utf-8", "replace"))
    
    sender, cmd, args = split_line(line)

    if cmd == RPL_END_OF_MOTD or cmd == ERR_NOMOTD:
        if flag1 == True:
            print("JOIN " + BOT_CHANNEL, file = handle)
            flag1 = False
    elif cmd == ERR_NICKNAMEINUSE:
        print("NICK " + BOT_NICK + str(random.randrange(1,1000)), file = handle)
    elif cmd == "PING":
        print("PONG :" + " ".join(args), file = handle)
    elif cmd == "PRIVMSG":
        msg = " ".join(args)
        #if msg.startswith("!radio"):  # send only with !radio msgs
        if msg.startswith("!"): # use ! in front of msgs in order to remove the receive confirmation loop of msgs
            continue        
#        sender = line.split("!")[0].replace(":", "")
        from_nick = sender.partition("!")[0]
        #Send to Radio via local WebServer 
        r = requests.post('http://localhost:8080', data={"postfield": from_nick + ": " + msg})
        time.sleep(10)  # Wait 10 seconds to send via radio mode PSK500R - 4 for mode PSK1000R
