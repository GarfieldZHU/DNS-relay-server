#coding=utf-8
#__author__ = 'Garfield'
# input module, read ip-domain pairs from file


def load_table(file_name):
    table = {}
    try:
        print("> Trying to open the file...")
        f = open(file_name)
    except IOError:
        print("> Fail to open the file", file_name)
        return None
    else:
        for eachLine in f:
            #print(eachLine)
            mapping_pair = eachLine.rstrip().split(' ', 2)
            table[mapping_pair[1]] = mapping_pair[0]
        f.close()
        return table
