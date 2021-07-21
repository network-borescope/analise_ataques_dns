# -*- coding: utf-8 -*-
import sys


cidrs = []

def site_from_ip_addr(addr):
    cidr = 32

    # Initialize net and binary and netmask with addr to get network
    net_ip = []
    for i in range(4):
        net_ip.append(int(addr[i]) & 255)

    for cidr in cidrs:
        found = True
        for i in range(4):
            if (net_ip[i] & cidr[3][i]) != cidr[2][i]:
                found = False
                break

        if found: return (cidr)

    return None

def site_from_ip(ip):
    addr = ip.split('.')
    return site_from_ip_addr(addr)


def load_ips(filename):

    with open(filename, encoding='utf8') as file:
        for line in file:
            if line[0] == '#': continue
            a = line.strip().split(";")
            nets = a[4].split(",")
            if a[4] == '': continue
            for s in nets:

                # Get address string and CIDR string from command line
                (addrString, cidrString) = s.split('/')
                addr = addrString.split('.')
                cidr = int(cidrString)

                # Initialize the netmask and calculate based on CIDR mask
                mask = [0, 0, 0, 0]
                for i in range(int(cidrString)):
                    mask[i//8] = mask[i//8] + (1 << (7 - i % 8))

                # Initialize net and binary and netmask with addr to get network
                net = []
                for i in range(4):
                    net.append(int(addr[i]) & mask[i])

                cidr = [ a[1], s, net, mask, a[2], a[3], a[0] ]
                cidrs.append( cidr )

                # print(cidr)

load_ips("pop_df_lat_lon.txt")

#s = site_from_ip("200.130.1.0")
#print("-------------")
#print(s)

