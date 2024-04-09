from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

def main():
    query_packet = IP(dst = '8.8.8.8')/UDP(sport = 24601,dport = 53)/DNS(rd = 1, qdcount = 1,qd = DNSQR(qname='www.amazon.com.')) 
    print(query_packet.show())
    reply_packet = sr1(query_packet)
    print(reply_packet.show())
    
if __name__ == '__main__':
    main()