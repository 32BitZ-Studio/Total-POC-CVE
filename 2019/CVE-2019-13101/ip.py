import re

def extractIP(ipStr):
    l = re.split('(.*)\.(.*)\.(.*)\.(.*)-(.*)', ipStr)
    rangeIp = l[-3:-1]
    rangeRede = l[1:4]
    
    rede = rangeRede[0]+"."+rangeRede[1]+"."+rangeRede[2]
    start = rangeIp[0]
    end = rangeIp[1]
    return [rede,start, end]
