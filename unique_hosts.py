print('Importing modules...\n')

from scapy.all import *
import sys

def uniques(pcap):
    print('Importing pcap...\n')
    packets = rdpcap(pcap)
    parts = []
    unique_hosts = set()

    print('Splitting...\n')
    for packet in packets:
        splits = (str(packet).split('\\r\\n'))
        for split in splits:
            parts.append(split.strip())

    print('Filtering...\n')
    for part in parts:
        if part[0:4] == 'Host':
            unique_hosts.add(part[6:])

    for host in unique_hosts:
        print(host)

if __name__ == '__main__':
    uniques(sys.argv[1])