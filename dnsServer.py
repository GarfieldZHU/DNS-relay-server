#coding = utf-8
#__author__ = 'Garfield'

import socketserver
import struct
from loadTable import *

file_name = 'dnsrelay.txt'


class DnsQuestion:
    def __init__(self, data):
        i = 1
        self.domain = ''
        while True:
            d = data[i]
            if d == 0:
                #ASCII = 0, then end up the deal
                break
            elif d < 32:
                #Add '.' between domain address
                self.domain += '.'
            else:
                self.domain = self.domain + chr(d)
            i += 1
        self.package = data[0: i + 1]
        (self.type, self.classify) = struct.unpack('!HH', data[i + 1: i + 5])
        self.len = i + 5

    def get_bytes(self):
        return self.package + struct.pack('!HH', self.type, self.classify)


class DnsReply:
    def __init__(self, ip):
        self.name = 49164
        self.type = 1
        self.classify = 1
        self.time = 190
        self.datalength = 4
        self.ip = ip

    def get_bytes(self):
        pack = struct.pack('!HHHLH', self.name, self.type, self.classify, self.time, self.datalength)
        iplist = self.ip.split('.')
        pack = pack + struct.pack('BBBB', int(iplist[0]), int(iplist[1]), int(iplist[2]), int(iplist[3]))
        return pack


class DnsAnalyzer:
    #DNS analyzer is used to unpack and analyse data in DNS requests
    #As be a frame, it need initialized by DnsQuestion
    def __init__(self, data):
        (self.Id, self.Flags, self.Questions, self.Answers, self.Authority, self.Addition) = \
            struct.unpack('!HHHHHH', data[0: 12])
        self.query = DnsQuestion(data[12:])

    def get_domain(self):
        #get the domain in Question part of DNS package
        return self.query.domain

    def set_ip(self, ip):
        #set ip of reply package
        self.Answer = DnsReply(ip)
        self.Answers = 1
        self.Flags = 33152

    def get_package(self):
        pack = struct.pack('!HHHHHH', self.Id, self.Flags, self.Questions, self.Answers, self.Authority, self.Addition)
        pack = pack + self.query.get_bytes()
        if self.Answers != 0:
            package = pack + self.Answer.get_bytes()
        return pack


class DnsUdpHandler(socketserver.BaseRequestHandler):
    #request handle class
    #UdpHandler is used to handle DNS query
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        analyzer = DnsAnalyzer(data)
        dnsmap = DnsRelayServer.mapping
        if analyzer.query.type == 1:
            #if receive a query request,then response it
            domain = analyzer.get_domain()
            if dnsmap.__contains__(domain):
                analyzer.set_ip(dnsmap[domain])
                socket.sendto(analyzer.get_package(), self.client_address)
            else:
                socket.sendto(data, self.client_address)
        else:
            socket.sendto(data, self.client_address)


class DnsRelayServer:
    #dns relay
    mapping = {}

    def __init__(self, port=8008):
        self.port = port

    @staticmethod
    def load_map():
        mapping = load_table(file_name)
        #variable map is a dictionary whose key is domain address and value is ip.
        if mapping is not None:
            print('> OK. Table has been loaded.')
        #print(self.mapping)

    def startup(self):
        HOST, PORT = 'localhost', self.port
        server = socketserver.UDPServer((HOST, PORT), DnsUdpHandler)
        server.serve_forever()