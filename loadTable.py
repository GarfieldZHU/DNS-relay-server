#coding=utf-8
#input module, read ip-domain pairs from file


def load_table(file_name):
    table = {}
    f = open(file_name)
    for eachLine in f:
        #print(eachLine)
        mapping_pair = eachLine.rstrip().split(' ', 2)
        table[mapping_pair[1]] = mapping_pair[0]
    f.close()
    return table