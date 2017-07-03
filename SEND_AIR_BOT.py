import socket
import requests
import time


nick = "airbotTX"
network = "127.0.0.1"
port = 6667
irc = socket.socket()
handle = irc.makefile(mode = "rw", buffering = 1, encoding = "utf-8", newline = "\r\n")

chan = "#zonkeynet"
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
        if msg.startswith("!radio"):  # only !radio msgs
            sender = line.split("!")[0].replace(":", "")
                           # first a test
            r = requests.post('http://localhost:8080', data={"postfield":sender + ": " + msg})
            time.sleep(10)  # 10 seconds for the RADIO mode PSK500R - 4 for PSK1000R mode
