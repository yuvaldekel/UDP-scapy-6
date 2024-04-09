from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

def main():
    dns_packet = IP(dst = '8.8.8.8')/UDP(sport = 24601,dport = 53)/DNS(rd = 0, qdcount = 1,qd = DNSQR(qname='www.google.com.')) 
    send(dns_packet)
    
if __name__ == '__main__':
    main()