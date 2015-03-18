#coding=utf-8
#__author__ = 'Garfield'
#Copyright = 'BUPT-Garfield, 03, 2015'
#This is main part of dns relay server

from loadTable import *

file_name = 'dnsrelay.txt'
table = {}

if __name__ == '__main__':
    table = load_table(file_name)
    print(table)
    #while True:
     #   pass