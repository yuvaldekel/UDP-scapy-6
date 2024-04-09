from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *
import re

def check_input(domain):
    return re.search("^([\w\d-]+\.){2,}([\w\d]+)(\.|)$", domain)

def find_ip(packet):
    answer = packet[DNS].an
    count = packet[DNS].ancount 

    if answer != None:
        answer = answer[count - 1]
        if answer.type != 1:
            return None
        return answer.rdata
    else:
        return None

def main():
    while True:
        domain = input("Please enter the domain you want to query: ")
        if check_input(domain):
            break
    
    if not domain.endswith('.'):
        domain = domain + '.'

    query_packet = IP(dst = '8.8.8.8')/UDP(sport = 24601,dport = 53)/DNS(rd = 1, qdcount = 1,qd = DNSQR(qname=domain)) 
    reply_packet = sr1(query_packet)
    #print(reply_packet.show())
    ip = find_ip(reply_packet)
    if ip == None:
        print("The server didn't find an answer for the specified domain \"{}\"".format(domain))
    else:
        print("The ip of the domain {} is {}".format(domain, ip))

    
if __name__ == '__main__':
    main()