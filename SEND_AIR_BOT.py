import socket
import requests
import time

nick = "airBOT_send"
network = "127.0.0.1"
port = 6667
irc = socket.socket()
handle = irc.makefile(mode="rw", buffering=1, encoding="utf-8", newline="\r\n")

chan = "#zonkeynet"
irc.connect((network,port))

print("PASS *", file=handle)
print("NICK " + nick, file=handle)
print("USER AirBot 0 * :BridgeBot", file=handle) 


flag1=True

for line in handle:
    line = line.strip()
    print(line.encode("utf-8", "replace"))
    if line[:4] == "PING":
        print("PONG :" + line.split(":")[1], file=handle)
        if flag1==True:
            print("JOIN " + chan, file=handle)
            flag1=False
    elif "PRIVMSG" in line:
        msg = ":".join(line.split(":")[2:])
        if msg.startswith("!radio"): #resend only !radio msgs
            sender = line.split("!")[0].replace(":","")
            #Post Request to AirChat Webserver
            r = requests.post('http://localhost:8080', data={"postfield":sender + ": " + msg}) #AirChat/ZonkeyNet_WebServer_Address
            time.sleep(10) #10 seconds
