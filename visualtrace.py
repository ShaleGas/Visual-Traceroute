#!/usr/bin/python
import socket
import select
import requests
import json
import simplekml
import time
import collections
import argparse
import os
import sys
import webbrowser
import re
#from scapy.all import *

def send(destname, ttl, args):
#sends UDP datagrams, takes in hostname 'destname'

    #port for sending on
    port = args.port
    #Socket for recieving icmp replies
    rec_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
    #bind to listning port
    rec_socket.bind(("", port))

    #Socket for sending UDP protocol datagrams
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))

    #Setting the ttl option on the datagrams
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    #Use socket to send the datagram
    send_socket.sendto("",(destname, port))
    time_sent = time.time()

    #print output in a traceroute-esque fashion
    #print "%s: to %s" % (ttl, destname)

    #close socket
    send_socket.close()

    return (rec_socket, time_sent)



def listen(rec_socket):



    while True:

        timeout = False
        addr = '192.168.1.254'
        time_rec = ''

        ready = select.select([rec_socket], [], [], 5)

        if ready[0] == []:
            print "timeout"
            timeout = True
            return (time_rec, addr, timeout)
            break

        time_rec = time.time()
        packet, (addr, port) = rec_socket.recvfrom(512)
        #print addr
        return (time_rec, addr, timeout)
        break


def trace(destip, args):

    ttl = 1
    maxhops = args.TTL

    trace1 = []
    trace2 = []
    trace3 = []

    probes = trace1, trace2, trace3

    for h in range(maxhops):

        for p in range(len(probes)):

            rec_socket, time_sent = send(destip, ttl, args)
            out = listen(rec_socket)
            print "(probe %s) hop %s: %s" % (p +1, ttl, out[1])
            probes[p].append(out[1])

        if out[1] == destip:
            print "done"
            break

        else:
            ttl += 1

    print "max hops reached before destination ip..."




    return probes

def filterip(probes):

    for x in range(10):

        for p in range(len(probes)):

            for index, a in enumerate(probes[p]):
                #if timeout map backward
                # if a == '0.0.0.0':
                #     trace1.remove(trace1[index])

                if re.search('(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)', a):
                    #print "popped %s" %(index)
                    probes[p].pop(index)

    return probes

def geoip(iplist):

    ipgeolist = []
    ipgeodict = collections.OrderedDict()

    for ip in iplist:

        #Make request to GeoAPI
        r = requests.get('http://freegeoip.net/json/' + ip)
        ipgeolist.append(r.json()['longitude'])
        ipgeolist.append(r.json()['latitude'])
        ipgeolist.append(r.json()['city'])
        ipgeolist.append(r.json()['country_name'])
        #print r.json()['longitude']
        #print r.json()['latitude']
        ipgeodict[ip] = ipgeolist
        ipgeolist = []

    return ipgeodict

def makekml(ipgeodict, args):

    kml = simplekml.Kml()
    pinlist = []
    hop = 1

    for key, value in ipgeodict.items():

        #print key, value
        lon = str(value[0])
        lat = str(value[1])
        city = str(value[2])
        country = str(value[3])


        try:

            rdns = socket.gethostbyaddr(key)[0]

        except:

            rdns = "Unknown"

        if country and city == '':

            country = "Not Found."
            city = "Not Found."

        elif country == '':

            country = "Not Found."

        elif city == '':

            city = "Not Found."
        #print lon
        #print lat

        pin = kml.newpoint()  # lon, lat, optional height
        pin.name = "(#%s) %s (%s)" % (hop, rdns, key)
        pin.description = "City: %s\nCountry: %s " % (city,country)
        pin.coords = [(lon,lat)]
        pinlist.append((lon,lat))
        hop += 1

    line = kml.newlinestring()
    line.coords = pinlist
    line.extrude = 1 # sends line around the planet
    line.tessellate = 1
    line.style.linestyle.width = 5
    line.style.linestyle.color = simplekml.Color.blue


    kml.save(args.output)

def cmdargs():

    parser = argparse.ArgumentParser(prog="visualtrace")

    parser.add_argument('-d', '--destination', default='www.google.co.uk', type=str, help='Destination to trace to')
    parser.add_argument('-o', '--output', default='trace.kml', type=str, help='File to be used for KML')
    parser.add_argument('-p', '--port', default=33464, type=int, help='Port to use for receiving packets')
    parser.add_argument('-t', '--TTL', default=20, type=int, help='Maximum number of hops to target')
    parser.add_argument('-GM', action='store_true', help='Open a browser at Google Maps')
    parser.add_argument('-GE', action='store_true', help='Open Google Earth (OSX only)')

    arg = parser.parse_args()

    return arg

def oscheck():

    if sys.platform == "darwin":

        OS = "osx"

    elif sys.platform == "linux2":

        OS = "linux"

    elif sys.platform == "win32":

        OS = "windows"

    else:

        print "Can't establish running OS, exiting..."
        sys.exit()

    return OS

# def scapytrace(destname):


#     for i in range(1, 28):

#         pkt = IP(dst=destname, ttl=i) / UDP(dport=33434)

#         # Send the packet and get a reply
#         reply = sr1(pkt, verbose=0)

#         if reply is None:
#             # No reply =(
#             break
#         elif reply.type == 3:
#             # We've reached our destination
#             print "Done!", reply.src
#             break
#         else:
#             # We're in the middle somewhere
#             print "%d hops away: " % i , reply.src

def openbrowser():

    url = "http://maps.google.com/maps?q="
    webbrowser.open_new(url)

def openearth(args):


    if oscheck() == 'osx':

        filepath = os.getcwd()
        filepath = filepath + "/" + args.output
        print filepath

        os.system("open -a '/applications/Google Earth.app' %s" % (filepath))
    if oscheck() == 'windows':

        filepath = os.getcwd()
        filepath = filepath + "/" + args.output
        print filepath

        subprocess.call(['C:\Program Files\Google\Google Earth\client\googleearth.exe', "%s" ]) % filepath

    else:

        print "Can't open Google Earth on this platform, sorry."



def main():


    args = cmdargs()

    # oscheck()
    destip = socket.gethostbyname(args.destination)

    print "Starting trace to: %s" % (destip)

    traces = trace(destip, args)
    filteredips = filterip(traces)

    print "Fetching coodinates..."

    geoipdata = geoip(filteredips[0])

    print "Making kml..."
    makekml(geoipdata, args)



    print "%s saved to working directory." % (args.output)


    if args.GM == True:

        openbrowser()

    if args.GE == True:

        openearth(args)


if __name__ == '__main__':
    main()





