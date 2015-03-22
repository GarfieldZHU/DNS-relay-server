#coding=utf-8
#__author__ = 'Garfield'
#Copyright = 'BUPT-CS-Garfield, Class 4 Grade 3 ----- Date: 03, 2015'
#This is main part of dns relay server

from dnsServer import *


if __name__ == '__main__':
    dns_server = DnsRelayServer()
    dns_server.load_map()
    dns_server.startup()
    print('Finished')