#!/usr/bin/env python
# -*- coding: utf-8 -*-

# DXrele is an irc bot to deliver DX-infos, wx, aprs, METAR, TAF, SOLAR data to your specific irc channel.
# Coding started 01.01.2014. Author Simo Pätäri OH2LRE.
# DXrele is under MIT license. Source location: https://github.com/oh2lre/DXrele
# If you run DXrele on your own, drop me a note. It would be interesting to hear your experience :)
# DX info and solar data source is DXCluster.co.uk
# Aprs and wx data source is aprs.fi

import sys
import socket
import string
import requests
import json
import ast
import datetime
from time import sleep
from time import time

MCALL = "zonkeynet" # <-- add here your own call, create and activate a new user account for it on http://www.geonames.org/login
MNICK = "zonkey" # <-- add here your own nick, not bot nick, but your own nick, and you will get "log" info (in private) about requests to the bot.
APIKEY = "102606.MvVrKFqBmgnC3a6x" # <-- add here your own aprs.fi api key, get it from: http://aprs.fi/page/api
HOST = "chat.freenode.net" # <-- add here your irc server address
PORT = 6667 # <-- add here your irc server port address
VERSIO = "03.02.2017"
NICK = "HamBot" # <-- set your bot nick
IDENT = "HamBot" # <-- set same as your bot nick
REALNAME = "HamBot" # <-- you can tailor the name as you like
CHAN = "##ZonkeyNet" # <-- irc chan
readbuffer = ""

# greeting status dictionary, you can add more nicks here as you like.
tervehdys = { MNICK : False,
"oh2lre" : False}

# these are timers and counters used in the main while loop to select first part of the code or the next and run it every 60 seconds.
vekkari = 0
counter = 0
counter_solar = 0

#open irc connection
s = socket.socket()
s.connect((HOST,PORT))
s.send("NICK %s\r\n" % NICK)
s.send("USER %s %s bla :%s\r\n" % (IDENT,HOST,REALNAME))
sleep (10)
s.send("JOIN :%s\r\n" % CHAN)

# adds '*' to DX spots on >31000 kHz, so mark V/U/SHF infos with an asterisk
def c(sana,raja,freq):
    if freq[len(freq)-2] == ".":
        freq = freq[:len(freq)-2]
        print "int: " + str(int(freq))
    if int(freq) > 31000:
        if len(sana) < raja-1:
            tayte = [" " *x for x in range (0,((raja-1)-len(sana)))]
            return sana+tayte[len(tayte)-1]+" *"
        else:
            return sana + "*"
    else:
        return l(sana,raja)

    
# add enough space, a tabulator implemented with a list comprehension statement.
def l(sana,raja):
    if len(sana) < raja+1:
        tayte = [" " *x for x in range (0,((raja+1)-len(sana)))]
        return sana+tayte[len(tayte)-1]
    else:
        return sana

    
# add enough space, a tabulator implemented with a list comprehension statement. and add '.0' to f that do not have it.
def f(sana,raja,dxkutsu,dxkutsuraja):
    if sana[len(sana)-2] != ".":
        sana = sana + ".0"
    if len(sana) < raja+1:
        if len(dxkutsu) - dxkutsuraja == 1 and len(sana) == 7:
            return " "+sana
        if len(dxkutsu) - dxkutsuraja == 2 and len(sana) == 7:
            return " "+sana
        if len(dxkutsu) - dxkutsuraja == 3 and len(sana) == 7:
            return " "+sana
        if len(dxkutsu) - dxkutsuraja == 1 and len(sana) == 6:
            return "  "+sana
        if len(dxkutsu) - dxkutsuraja == 2 and len(sana) == 6:
            return " "+sana
        if len(dxkutsu) - dxkutsuraja == 3 and len(sana) == 6:
            return " "+sana
        tayte = [" " *x for x in range (0,((raja+1)-len(sana)))]
        return tayte[len(tayte)-1]+sana
    else:
        return sana

    
# retrieve solar data and print on the channel or in private
def HaeSolar(counter_solar,line,supajuusa):
    endpoint = "http://www.dxcluster.co.uk/api/solar"
    headers = {"User-Agent" : NICK + "/" + VERSIO + " @ " + CHAN + ", " + MNICK}

    response = requests.get(endpoint, headers = headers)

    data = ast.literal_eval(response.text)
    
    if counter_solar < data["id"]:
        counter_solar = data["id"]
        date = data["date"]
        flux = data["flux"]
        aindex = data["a"]
        kindex = data["k"]
        ssn = data["ssn"]
        SOLAR = "-> SOL " + date[11:13] + "Z: SFI=" + flux + " R=" + ssn + " A=" + aindex + " K=" + kindex
        print SOLAR
        if supajuusa == 1:
            s.send("PRIVMSG %s :%s\r\n" % (CHAN,SOLAR))
        else:
            s.send("PRIVMSG %s :%s\r\n" % (parsaanikki(line[0]),SOLAR))
        
    return counter_solar


# retrieve DX-info data and print on the channel or in private    
def HaeInfot(counter):
    endpoint = "http://www.dxcluster.co.uk/api/all"
    headers = {"User-Agent" : NICK + "/" + VERSIO + " @ " + CHAN + ", " + MNICK}

    response = requests.get(endpoint, headers = headers)

    data = json.loads(response.content)

    length = len(data)

    for i in range(length-1,-1,-1):
        mtime = []
        if counter < data[i]["nr"]:
            counter = data[i]["nr"]
            dxcall = data[i]["dxcall"]
            call = data[i]["call"]
            mtime = data[i]["mytime"]
            
            # you can tailor the line below to filter infos by spotted call or by spotter. The line below allows only German prefixes as dx call or the spotter's prefix
            if dxcall[:2] == "DL" or call[:2] == "DL":
                if data[i]["freq"][0] == "2" and len(data[i]["freq"]) == 6:
                    data[i]["freq"] = "1" + data[i]["freq"]
                    pit = len(data[i]["call"])
                    data[i]["call"] = data[i]["call"][:pit-1]
                if data[i]["dxcall"][:2] == "Z6":
                    data[i]["dx_name"] = "PROBABLY KOSOVO"
                if data[i]["dxcall"][:2] == "TO":
                    data[i]["dx_name"] = "FRANCE"
                dxkutsuraja = 10
                dxkutsu = c(data[i]["dxcall"],dxkutsuraja,data[i]["freq"])
                DXINFO = dxkutsu + f(data[i]["freq"],9,dxkutsu,dxkutsuraja) + " " + mtime[12:] + "Z" + " de " + l(data[i]["call"],9) + l(data[i]["comment"],31) + data[i]["dx_name"]
                s.send("PRIVMSG %s :%s\r\n" % (CHAN,DXINFO))
                sleep(0.1)
    
    return counter


# greeting function
def sayhello(line):
    if line[2] == NICK:
        nikki = parsaanikki(line[0])
    else:
        nikki = CHAN

    if line[0][1:7] == MNICK and tervehdys[MNICK] == False:
        s.send("PRIVMSG %s :Hi, you here too LOL\r\n" % (nikki))
        tervehdys[MNICK] = True
    if line[0][1:7] == "oh2lre" and tervehdys["oh2lre"] == False:
        s.send("PRIVMSG %s :Hi oh2lre, you here too LOL\r\n" % (nikki))
        tervehdys["oh2lre"] = True

        
# function to list all commands        
def komennot(line):
    if line[3] == ":??":
        if line[2] == NICK:
            nikki = parsaanikki(line[0])
        else:
            nikki = CHAN

        s.send("PRIVMSG %s :Send commands to teh bot on this channel or in private:\r\n" % (nikki))
        s.send("PRIVMSG %s :1) .sh/dx [band] [optionally, number of last spots between 1-7, default is 5]\r\n" % (nikki))        
        s.send("PRIVMSG %s :bands: 160m, 80m, 40m, 30m, 20m, 17m, 15m, 12m, 10m, 6m, 4m, 2m, 70cm, 23cm e.g: .sh/dx 10m 7  or  .sh/dx 2m\r\n" % (nikki))
        s.send("PRIVMSG %s :2) .sh [dxcall] List up to 10 last spots for the call, e.g: .sh oh2k\r\n" % (nikki))        
        s.send("PRIVMSG %s :3) .wx [wx-station] Print wx-station data retrieved from aprs.fi, e.g: .wx oh2kxh\r\n" % (nikki))        
        s.send("PRIVMSG %s :4) .aprs [call-ssid] Latest location retrieved from aprs.fi  5) .sol  Print last solar data\r\n" % (nikki))        
        s.send("PRIVMSG %s :6) .wxp [city] Crowdsourced weather forecast, e.g: .wxp monaco \r\n" % (nikki))                
        s.send("PRIVMSG %s :7) .metar [ICAO aeropuerto code] Aviation weather, e.g: .metar katl  World's biggest aeropuerto\r\n" % (nikki))
        s.send("PRIVMSG %s :8) .taf [ICAO aeropuerto code] Aviation weather forecast, e.g: .taf efma  OH0-aeropuerto\r\n" % (nikki))        

        
# retrieve specific band spots, the sh/dx 10m command
def HaeBand(band,count,nikki):
    if count == "1" or count == "2" or count == "3" or count == "4" or count == "5" or count == "6" or count == "7":
        count = int(count)
    else:
        count = 5

    endpoint = "http://www.dxcluster.co.uk/api/data_band/" + band
    headers = {"User-Agent" : NICK + "/" + VERSIO + " @ " + CHAN + ", " + MNICK}

    response = requests.get(endpoint, headers = headers)

    data = json.loads(response.content)

    length = len(data)
        
    for i in range(0,count):
        mtime = []
        dxcall = data[i]["dxcall"]
        call = data[i]["call"]
        mtime = data[i]["mytime"]
        if data[i]["freq"][0] == "2" and len(data[i]["freq"]) == 6:
            data[i]["freq"] = "1" + data[i]["freq"]
            pit = len(data[i]["call"])
            data[i]["call"] = data[i]["call"][:pit-1]
        if data[i]["dxcall"][:2] == "Z6":
            data[i]["dx_name"] = "PROBABLY KOSOVO"
        if data[i]["dxcall"][:2] == "TO":
            data[i]["dx_name"] = "FRANCE"
        dxkutsuraja = 10
        dxkutsu = c(data[i]["dxcall"],dxkutsuraja,data[i]["freq"])
        DXINFO = dxkutsu + f(data[i]["freq"],9,dxkutsu,dxkutsuraja) + " " + mtime[12:] + "Z" + " de " + l(data[i]["call"],9) + l(data[i]["comment"],31) + data[i]["dx_name"]
        s.send("PRIVMSG %s :%s\r\n" % (nikki,DXINFO))
    s.send("PRIVMSG %s :.\r\n" % (nikki))
    sleep(0.1)

    
# select band
def dxband(line):
    if line[2] == NICK:
        nikki = parsaanikki(line[0])
    else:
        nikki = CHAN
    if len(line) == 6:
        count = line[5]
    else:
        count = "5"
    if line[4] == "160m":
        HaeBand("160",count,nikki)
    elif line[4] == "80m":
        HaeBand("80",count,nikki)
    elif line[4] == "40m":
        HaeBand("40",count,nikki)
    elif line[4] == "30m":
        HaeBand("30",count,nikki)
    elif line[4] == "20m":
        HaeBand("20",count,nikki)
    elif line[4] == "17m":
        HaeBand("17",count,nikki)
    elif line[4] == "15m":
        HaeBand("15",count,nikki)
    elif line[4] == "12m":
        HaeBand("12",count,nikki)
    elif line[4] == "10m":
        HaeBand("10",count,nikki)
    elif line[4] == "6m":
        HaeBand("6",count,nikki)
    elif line[4] == "4m":
        HaeBand("4",count,nikki)
    elif line[4] == "2m":
        HaeBand("2",count,nikki)
    elif line[4] == "70cm":
        HaeBand("07",count,nikki)
    elif line[4] == "23cm":
        HaeBand("023",count,nikki)
 
        
# retrieve wx data from aprs.fi
def wx(line,supajuusa):
    nikki = parsaanikki(line[0])
    loppu = ""
    endpoint = "http://api.aprs.fi/api/get?name=" + line[4] + "&what=wx&apikey=" + APIKEY + "&format=json"
    headers = {"User-Agent" : NICK + "/" + VERSIO + " @ " + CHAN + " serving query for: " + nikki + ", " + MNICK}

    response = requests.get(endpoint, headers = headers)
        
    data = json.loads(response.content)
    if data["result"] == "ok" and data["found"] > 0:
        aika = datetime.datetime.utcfromtimestamp(int(data["entries"][0]["time"])).strftime('%Y-%m-%d %H:%M:%S')
        alku = data["entries"][0]["name"] + " @ " + aika + "Z: "
        for g in data["entries"][0]:
            if g != "name" and g!= "time":
                loppu += g + ": " + str(data["entries"][0][g]) + ", "
        if supajuusa == 1:
            s.send("PRIVMSG %s :%s\r\n" % (CHAN,alku+loppu[:len(loppu)-2]))
        else:
            s.send("PRIVMSG %s :%s\r\n" % (nikki,alku+loppu[:len(loppu)-2]))
        sleep(0.1)

        
# retrieve aprs data from aprs.fi
def aprs(line,supajuusa):
    nikki = parsaanikki(line[0])
    endpoint = "http://api.aprs.fi/api/get?name=" + line[4] + "&what=loc&apikey=" + APIKEY + "&format=json"
    headers = {"User-Agent" : NICK + "/" + VERSIO + " @ " + CHAN + " serving query for: " + nikki + ", " + MNICK}

    response = requests.get(endpoint, headers = headers)
        
    data = json.loads(response.content)
    if data["result"] == "ok" and data["found"] > 0:
        towncountry = {}
        aika = datetime.datetime.utcfromtimestamp(int(data["entries"][0]["lasttime"])).strftime('%Y-%m-%d %H:%M:%S')
        alku = data["entries"][0]["name"] + " @ " + aika + "Z: "
        towncountry = findplace(data["entries"][0]["lat"], data["entries"][0]["lng"])
        rivi = alku + "in " + towncountry["town"] + ", " + towncountry["country"]            
        print
        for i in data["entries"][0]:
            print i + ": " + str(data["entries"][0][i])
            if i == "comment":
                comment = str(data["entries"][0][i])
                rivi = alku + "in " + towncountry["town"] + ", " + towncountry["country"] + ", cmt: " + comment

        rivi = rivi.encode("utf-8")
        
        if supajuusa == 1:
            s.send("PRIVMSG %s :%s\r\n" % (CHAN,rivi))
        else:
            s.send("PRIVMSG %s :%s\r\n" % (nikki,rivi))
        sleep(0.1)
        print


# translate lat and lon into a place name with geonames.org
def findplace(lat,lon):
    location = {"town":"","country":""}
    endpoint = "http://api.geonames.org/findNearbyJSON?lat=" + lat + "&lng=" + lon + "&lang=fi&username=" + MCALL
    headers = {"User-Agent" : MCALL}

    response = requests.get(endpoint, headers = headers)
        
    data = json.loads(response.content)
    location["town"] = data["geonames"][0]["name"]
    location["country"] = data["geonames"][0]["adminName1"] + ", " + data["geonames"][0]["countryName"]

    return location


# parse user nick        
def parsaanikki(osoite):
    paikka = osoite.find("!")
    if paikka == -1:
        return osoite
    else:
        return osoite[1:paikka]

    
# function to search spots for a call, sh oh2k
def dxc(line,supajuusa):
    nikki = parsaanikki(line[0])
    endpoint = "http://www.dxcluster.co.uk/api/search_callsign"
    payload = {"callsigns":line[4]}
    response = requests.post(endpoint,data=payload)
    data = ast.literal_eval(response.text)
    for i in data:
        mtime = i["time"][:16]
            
        if i["freq"][0] == "2" and len(i["freq"]) == 6:
            i["freq"] = "1" + i["freq"]
            pit = len(i["call"])
            i["call"] = i["call"][:pit-1]
        dxkutsuraja = 10
        dxkutsu = c(i["dxcall"],dxkutsuraja,i["freq"])
        DXINFO = dxkutsu + f(i["freq"],9,dxkutsu,dxkutsuraja) + " " + mtime + "Z" + " de " + l(i["call"],9) + l(i["comment"],31)
        if supajuusa == 1:
            s.send("PRIVMSG %s :%s\r\n" % (CHAN,DXINFO))
        else:
            s.send("PRIVMSG %s :%s\r\n" % (nikki,DXINFO))            
        sleep(0.1)
    if supajuusa == 1:
        s.send("PRIVMSG %s :.\r\n" % (CHAN))
    else:
        s.send("PRIVMSG %s :.\r\n" % (nikki))            
            

# find lat and lon for a named city
def findlatlon(city):
    latlon = {"lat":"0","lon":"0","country":"NULLiA"}
    endpoint = "http://api.geonames.org/postalCodeLookupJSON?placename=" + city + "&maxRows=1&username=" + MCALL
    headers = {"User-Agent" : MCALL}
                
    response = requests.get(endpoint, headers = headers)
                    
    data = json.loads(response.content)
    print "len_postalcodes: " + str(len(data["postalcodes"]))
    if len(data["postalcodes"]) > 0:
        latlon["lat"] = data["postalcodes"][0]["lat"]
        latlon["lon"] = data["postalcodes"][0]["lng"]
        latlon["country"] = data["postalcodes"][0]["countryCode"]
                                
    return latlon


# replace scandinavian letters with a o a, take dots away. recursive laborous implementation, but works.
def rskand(line):
    nline = ""
    pit = len(line)

    for i in range(0,pit):
        #UTF-8
        if line[i].find("\xc3") == 0:
            if i < pit:
                if line[i+1].find("\xa4") == 0:
                    return rskand(line[:i]+"a"+line[i+2:])
                if line[i+1].find("\x84") == 0:
                    return rskand(line[:i]+"A"+line[i+2:])
                if line[i+1].find("\xb6") == 0:
                    return rskand(line[:i]+"o"+line[i+2:])
                if line[i+1].find("\x96") == 0:
                    return rskand(line[:i]+"O"+line[i+2:])
                if line[i+1].find("\xa5") == 0:
                    return rskand(line[:i]+"a"+line[i+2:])
                if line[i+1].find("\x85") == 0:
                    return rskand(line[:i]+"A"+line[i+2:])
                
        #ISO-8859-1
        if line[i].find("\xe4") == 0:
            return rskand(line[:i]+"a"+line[i+1:])
        if line[i].find("\xc4") == 0:
            return rskand(line[:i]+"A"+line[i+1:])
        if line[i].find("\xf6") == 0:
            return rskand(line[:i]+"o"+line[i+1:])
        if line[i].find("\xd6") == 0:
            return rskand(line[:i]+"O"+line[i+1:])
        if line[i].find("\xe5") == 0:
            return rskand(line[:i]+"a"+line[i+1:])
        if line[i].find("\xc5") == 0:
            return rskand(line[:i]+"A"+line[i+1:])

        if i == pit-1:
            return line

    return nline


# retrieve wx forecast from metwit.com
def wxp(line,supajuusa):
    nikki = parsaanikki(line[0])
    city = rskand(line[4])
    print city
    latlon = findlatlon(city)
    lat = str(latlon["lat"])
    print "lat:" + lat
    lon = str(latlon["lon"])
    print "lon:" + lon
    country = str(latlon["country"])
    print "country:" + country
    
    if country != "NULLiA":
        endpoint = "https://api.metwit.com/v2/weather/?location_lat=" + lat + "&location_lng=" + lon
        headers = {"User-Agent" : MCALL + " experimenting"}

        response = requests.get(endpoint, headers = headers)

        data = json.loads(response.content)
        pituus = len(data["objects"])
        print "pituus: " + str(pituus)
        kay = []
        if pituus == 0:
            kay.append(0)
        elif pituus < 6:
            kay = [i for i in range(0,pituus)]
        elif pituus < 11:
            kay.append(0)
            kay = [i for i in range(pituus) if i % 2 != 0]
        elif pituus > 10:
            kay.append(0)            
            kay.append(1)
            kay.append(5)
            kay.append(10)
        print kay

        for j in kay:
            timestamp = ""
            status = ""
            temp = ""
            humidity = ""
            wind_dir = ""
            wind_spd = ""
            
            for n in data["objects"][j]:
                if n == "timestamp":
                    timestamp = data["objects"][j]["timestamp"][:13] + "Z"
                if n == "weather":
                    for k in data["objects"][j]["weather"]:
                        if k == "status":
                            status = data["objects"][j]["weather"]["status"]
                        if k == "measured":
                            for t in data["objects"][j]["weather"]["measured"]:
                                if t == "temperature":
                                    temp =  str(data["objects"][j]["weather"]["measured"]["temperature"]-272)
                                if t == "humidity":
                                    humidity =  str(data["objects"][j]["weather"]["measured"]["humidity"])
                                if t == "wind_direction":
                                    wind_dir =  str(data["objects"][j]["weather"]["measured"]["wind_direction"])
                                if t == "wind_speed":
                                    wind_spd =  str(data["objects"][j]["weather"]["measured"]["wind_speed"])
            WXP = city + ", " + country + " @ " + timestamp + ", status: " + status + ", temp:" + temp + "C, humidity:" + humidity + ", wind_dir:" + wind_dir + ", wind_spd:" + wind_spd
            WXP = WXP.encode("utf-8")
            print WXP

            if supajuusa == 1:
                s.send("PRIVMSG %s :%s\r\n" % (CHAN,WXP))
            else:
                s.send("PRIVMSG %s :%s\r\n" % (nikki,WXP))
            sleep(0.1)
        

# retrieve METAR data from geonames.org
def metar(line,supajuusa):
    nikki = parsaanikki(line[0])    
    metar = "NIL, NADA"
    loppu = "GAR NIX"
    viesti = ""
    #latlon = {"lat":"0","lon":"0","country":"NULLiA"}
    endpoint = "http://api.geonames.org/weatherIcaoJSON?ICAO=" + line[4] + "&username=" + MCALL
    headers = {"User-Agent" : MCALL}
                
    response = requests.get(endpoint, headers = headers)
                    
    data = json.loads(response.content)
    for i in data.keys():
        if i == "weatherObservation":
            ICA = data["weatherObservation"]["stationName"] + " " + data["weatherObservation"]["ICAO"]
            aika = data["weatherObservation"]["datetime"][:16]
            observation = data["weatherObservation"]["observation"]
            metar = ICA + " @ " + aika + "Z, " + observation
            loppu = ""
            for i in data["weatherObservation"]:
                j = data["weatherObservation"][i]
                if i == "stationName" or i == "ICAO" or i == "datetime" or i == "observation" or i == "countryCode" or i == "lng" or i == "lat":
                    pass
                else:
                    loppu += i + ": " + str(j) + ", "

    if metar == "NIL, NADA":
        viesti = "NIL, NADA, GAR NIX"
    else:
        viesti = loppu[:len(loppu)-2]

    if supajuusa == 1:
        if metar == "NIL, NADA":
            s.send("PRIVMSG %s :%s\r\n" % (CHAN,viesti))
        else:
            s.send("PRIVMSG %s :%s\r\n" % (CHAN,metar))
            s.send("PRIVMSG %s :%s\r\n" % (CHAN,viesti))
    else:
        if metar == "NIL, NADA":
            s.send("PRIVMSG %s :%s\r\n" % (nikki,viesti))
        else:
            s.send("PRIVMSG %s :%s\r\n" % (nikki,metar))
            s.send("PRIVMSG %s :%s\r\n" % (nikki,viesti))
    sleep(0.1)


# get TAF data by parsing it from html file that is retrieved from aviationweather.org 
def taf(line,supajuusa):
    nikki = parsaanikki(line[0])
    ICAO = line[4].upper()
    TAF = "NIL, NADA, GAR NIX"
    endpoint = "http://www.aviationweather.gov/adds/tafs?station_ids=" + ICAO + "&std_trans=standard&submit_taf=Get+TAFs"
    print endpoint
    headers = {"User-Agent" : MNICK}
                
    response = requests.get(endpoint, headers = headers)
    
    if response.status_code == 200:
        res = ", ".join(response.text.split("\n     "))
        alku = res.find('size="+1">')+10
        loppu = res.find("</font></PRE>")
        TAF = ""
        for i in range(alku,loppu):
            TAF += res[i]
        TAF = ",".join(TAF.split(" ,"))        
        print TAF
        print len(TAF)
        TAF = TAF[:len(TAF)-4]
        print TAF
        if supajuusa == 1:
            s.send("PRIVMSG %s :%s\r\n" % (CHAN,TAF))
        else:
            s.send("PRIVMSG %s :%s\r\n" % (nikki,TAF))
        sleep(0.1)
    else:
        if supajuusa == 1:
            s.send("PRIVMSG %s :%s\r\n" % (CHAN,TAF))
        else:
            s.send("PRIVMSG %s :%s\r\n" % (nikki,TAF))
        sleep(0.1)
        

        
# main loop, main program
# it listens irc channel, then parses commands, and in the end gets new DX-infos and solar data every 60 seconds.
while 1:
    readbuffer = readbuffer+s.recv(1024)
    temp = string.split(readbuffer, "\n")
    readbuffer = temp.pop()
    
    for line in temp:
        line = rskand(line)
        print "Line: " + line
        line = string.rstrip(line)
        line = string.split(line)
        
        if (line[0] == "PING"):
            s.send ("PONG %s\r\n" % line[1])
            print "Sends: PONG %s\r\n" % line[1]
        if line[0][1:13] != HOST and line[0] != "PING":
            if len(line) > 3:
                sayhello(line)
            print "line length is: " + str(len(line))
            if len(line) == 5 or len(line) == 6:
                if line[3] == ":.sh/dx":
                    s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                    dxband(line)
            if len(line) == 5 and line[3] == ":.wx" and line[2] == NICK:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                wx(line,0)
            if len(line) == 5 and line[3] == ":.wx" and line[2] == CHAN:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                wx(line,1)
            if len(line) == 4 and line[3] == ":??":
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                komennot(line)
            if len(line) == 5 and line[3] == ":.sh" and line[2] == NICK:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                dxc(line,0)
            if len(line) == 5 and line[3] == ":.sh" and line[2] == CHAN:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                dxc(line,1)
                
            if len(line) == 5 and line[3] == ":.aprs" and line[2] == NICK:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                aprs(line,0)
            if len(line) == 5 and line[3] == ":.aprs" and line[2] == CHAN:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                aprs(line,1)
                
            if len(line) == 5 and line[3] == ":.wxp" and line[2] == NICK:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                wxp(line,0)
            if len(line) == 5 and line[3] == ":.wxp" and line[2] == CHAN:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                wxp(line,1)                

            if len(line) == 5 and line[3] == ":.metar" and line[2] == NICK:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                metar(line,0)
            if len(line) == 5 and line[3] == ":.metar" and line[2] == CHAN:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                metar(line,1)                

            if len(line) == 5 and line[3] == ":.taf" and line[2] == NICK:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                taf(line,0)
            if len(line) == 5 and line[3] == ":.taf" and line[2] == CHAN:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                taf(line,1)                

            if len(line) == 4 and line[3] == ":.sol" and line[2] == NICK:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                HaeSolar(-1,line,0)                
            if len(line) == 4 and line[3] == ":.sol" and line[2] == CHAN:
                s.send("PRIVMSG %s :  $ %s\r\n" % (MNICK,line))
                HaeSolar(-1,line,1)                                
                
            
    if vekkari == 0 and counter == 0:
        print "Vekkari: " + str(vekkari) + " Counter: " + str(counter) + " counter_solar: " + str(counter_solar)
        counter = HaeInfot(counter)
        counter_solar = HaeSolar(counter_solar,line,1)
        vekkari = 1
        start = time()
        print "First end, start_time: " + str(start)
    else:
        done = time()
        elapsed = done - start
        print "HaenInfot, else, elapsed: " + str(elapsed) + ", Counter: " + str(counter) + " counter_solar: " + str(counter_solar)
        if elapsed > 60:
            counter = HaeInfot(counter)
            counter_solar = HaeSolar(counter_solar,line,1)            
            start = time()
    
    print "while loop in end"
    
