#!/usr/bin/env python3
import socket
import requests
import time

nick = "airBOT_TX"
network = "chat.freenode.net"
port = 6667
irc = socket.socket()
handle = irc.makefile(mode="rw", buffering=1, encoding="utf-8", newline="\r\n")

CHARS_PER_SECOND = 10.5
HEAD_SECONDS = 2.1

chan = "#ZonkeyNet"
irc.connect((network,port))

#print("PASS *", file=handle)
print("NICK " + nick, file=handle)
print("USER airBot_TX 0 * :AirBot_TX", file=handle) 

def parse_message(rawline):
    """Helper function to process line from irc"""
    sender, _, rest = rawline.partition(' ')
    sender = sender[1:]
    command, _, rest = rest.partition(' ')
    args = []
    while (len(rest) > 0):
        if rest[0] == ':': 
            args.append(rest[1:])
            break
        arg, _, rest = rest.partition(' ')
        args.append(arg)
    return {'sender': sender, 'command': command, 'args': args}

def send_command(cmd):
    print(cmd, file = handle)
    
for line in handle:
    line = line.strip()
    print(line.encode("utf-8", "replace"))
    li = parse_message(line)
    if line[:4].upper() == "PING":
        send_command("PONG" + line[4:])
    elif li['command'] == "376" or li['command'] == "422":
        # END_OF_MOTD / MOTD_NOT_FOUND - when we connected completely to server
        send_command("JOIN " + chan)
    elif li['command'] == "PRIVMSG":
        # if PRIVMSG to channel 'chan'
        if li['args'][0].upper() == chan.upper(): 
            msg = li['args'][1]
            if msg.startswith("!"):
                continue
            if msg.startswith("@"):
                continue
            sender, _, __ = li['sender'].partition('!') 
            p = sender + ": " + msg
            r = requests.post('http://localhost:8080', data={"postfield": p})
            time.sleep(HEAD_SECONDS + len(p) / CHARS_PER_SECOND)