#coding = utf-8
#__author__ = 'Garfield'

##    [dns package structure]
##     0 1 2    ...       31
##    +---------------------+
##    |         Header      | package head including port and address, includes 3 lines
##    +---------------------+
##    |       Question      | the question for the name server
##    +---------------------+
##    |        Answer       | RRs answering the question
##    +---------------------+
##    |      Authority      | RRs pointing toward an authority
##    +---------------------+
##    |      Additional     | RRs holding additional information
##    +---------------------+

##    [dns Header structure]
##                                   1  1  1  1  1  1
##     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                      ID                       |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                    QDCOUNT                    |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                    ANCOUNT                    |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                    NSCOUNT                    |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                    ARCOUNT                    |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

##    [dns Question structure]
##                                   1  1  1  1  1  1
##     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                                               |
##    /                     QNAME                     /
##    /                                               /
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                     QTYPE                     |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                     QCLASS                    |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

##    [dns Answer structure]
##                                   1  1  1  1  1  1
##     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                                               |
##    /                                               /
##    /                      NAME                     /
##    |                                               |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                      TYPE                     |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                     CLASS                     |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                      TTL                      |
##    |                                               |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
##    |                   RDLENGTH                    |
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
##    /                     RDATA                     /
##    /                                               /
##    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


import socketserver
import struct
import socket
import threading
import sys
from loadTable import *

file_name = 'dnsrelay.txt'
outer = ('114.114.114.114', 53)
BUFSIZE = 1024
global domainmap
id_map = {}
#ip_map saves pairs of id and the ip where it comes from
#ip_map saves pairs of id that relay-server sets and id from client, like(1, 2331)
task_queue = []
#task_queue saves the pairs of socket, the data waiting to be relayed and client's ip


class DnsQuery:
    #from question part, get domain address which need to be queried
    def __init__(self, data):
        i = 1
        self.domain = ''
        self.ip = ''
        while True:
            d = data[i]
            if d == 0:
                #ASCII = 0, then end up the deal
                break
            elif d < 32:
                #Add '.' between domain address
                self.domain += '.'
            else:
                self.domain += chr(d)
            i += 1
        self.package = data[0: i + 1]
        (self.type, self.classify) = struct.unpack('!HH', data[i + 1: i + 5])
        self.len = i + 5

    def get_bytes(self):
        return self.package + struct.pack('!HH', self.type, self.classify)


class DnsAnswer:
    #write the answer part in dns package if needs
    def __init__(self, ip):
        self.name = 49164
        self.type = 1
        self.classify = 1
        self.ttl = 190
        self.datalength = 4
        self.ip = ip

    def get_bytes(self):
        pack = struct.pack('!HHHLH', self.name, self.type, self.classify, self.ttl, self.datalength)
        iplist = self.ip.split('.')
        pack = pack + struct.pack('BBBB', int(iplist[0]), int(iplist[1]), int(iplist[2]), int(iplist[3]))
        return pack


class DnsAnalyzer:
    #DNS analyzer is used to unpack and analyse data in DNS requests
    #As be a frame, it need initialized by DnsQuery
    def __init__(self, data):
        (self.Id, self.Flags, self.QdCount, self.AnCount, self.NsCount, self.ArCount) = \
            struct.unpack('!6H', data[0: 12])
        self.query = DnsQuery(data[12:])

    def get_id(self):
        return self.Id

    def set_id(self, i):
        self.Id = i

    def get_qr(self):
        qr = (self.Flags >> 15) % 2
        #print('> QR is : %d' % qr)
        return qr

    def get_domain(self):
        #get the domain in Question part of DNS package
        return self.query.domain

    def set_ip(self, ip):
        #set ip of reply package
        self.Answer = DnsAnswer(ip)
        self.AnCount = 1
        self.Flags = 33152

    def get_ip(self, reply):
        #get IP from Answer part when the it is reply package
        ip = ''
        i = self.query.len + 24
        #according structure of Answer, RDATA starts from the 13th byte of Answer
        ip += str(reply[i])
        ip += '.'
        ip += str(reply[i+1])
        ip += '.'
        ip += str(reply[i+2])
        ip += '.'
        ip += str(reply[i+3])
        #print('%d.%d.%d.%d' % (reply[i], reply[i+1], reply[i+2], reply[i+3]))
        return ip

    def response(self):
        pack = struct.pack('!6H', self.Id, self.Flags, self.QdCount, self.AnCount, self.NsCount, self.ArCount)
        pack = pack + self.query.get_bytes()
        if self.AnCount != 0:
            pack += self.Answer.get_bytes()
        return pack

    def request(self, i):
        tmp = 0xff
        tmp = i & tmp
        self.set_id(tmp)
        pack = struct.pack('!6H', self.Id, self.Flags, self.QdCount, self.AnCount, self.NsCount, self.ArCount)
        pack = pack + self.query.get_bytes()
        return pack


class DnsUdpHandler(socketserver.BaseRequestHandler):
    #request handle class
    #UdpHandler is used to handle DNS query
    def handle(self):
        data = self.request[0].strip()
        sock = self.request[1]
        analyzer = DnsAnalyzer(data)
        dnsmap = domainmap
        #print(dnsmap)
        if analyzer.query.type == 1:
            #print(data)
            #query wants the ip of domain
            domain = analyzer.get_domain()
            if dnsmap.__contains__(domain):
                #domain is found on local server
                analyzer.set_ip(dnsmap[domain])
                print('- Domain exists on local server..')
                print('> Domain:  ' + domain)
                print('> Ip    :  ' + dnsmap[domain] + '\n')
                sock.sendto(analyzer.response(), self.client_address)
                #print('- Package: %s\n' % analyzer.response())
            else:
                #add the task to task_queue, waiting to be relayed
                print('- Domain doesn\'t exist on local server. Request it from outer server.')
                task_queue.append((sock, data, self.client_address))
        else:
            sock.sendto(data, self.client_address)


class DnsRelayServer:
    #dns relay server

    def __init__(self, port=53):
        self.port = port
        self.relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    @staticmethod
    def load_map():
        global domainmap
        domainmap = load_table(file_name)
        #variable map is a dictionary whose key is domain address and value is ip.
        if domainmap is not None:
            print('--OK. Table has been loaded.')

    def startup(self):
        #start up the relay thread and server thread
        host, port = '127.0.0.1', self.port
        print('> Server startup...\n> Bind UDP socket -- address, port: %s : %s\n' % (host, port))
        threading.Thread(target=self.relay_thread).start()
        server = socketserver.UDPServer((host, port), DnsUdpHandler)
        server.serve_forever()

    def relay_thread(self):
        #start a loop to deal with task queue
        index = 0
        while True:
            if len(task_queue) > 0:
                #when there exists tasks
                if index < 1024:
                    index += 1
                else:
                    index = 0

                sock, data, client_address = task_queue[0]
                analyzer = DnsAnalyzer(data)
                id_map[index] = analyzer.get_id()
                self.relay_sock.sendto(analyzer.request(index), outer)

                reply, addr = self.relay_sock.recvfrom(BUFSIZE)
                print('- Address: %s\n- Package: %s\n' % (addr, reply))
                reply_analyzer = DnsAnalyzer(reply)
                reply_ip = reply_analyzer.get_ip(reply)
                print('- Get reply from outer server..')
                print('> Domain:  ' + reply_analyzer.get_domain())
                print('> Ip    :  ' + reply_ip + '\n')
                rest = reply[2:]
                Id = id_map[index]
                reply = struct.pack('!H', Id) + rest
                sock.sendto(reply, client_address)
                #print(reply)
                task_queue.pop(0)
