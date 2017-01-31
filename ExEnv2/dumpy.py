from ctypes import *
from winpcapy import *
import time
import sys
import string
import platform

if platform.python_version()[0] == "3":
	raw_input=input
header = POINTER(pcap_pkthdr)()
pkt_data = POINTER(c_ubyte)()
alldevs=POINTER(pcap_if_t)()
errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
fp=pcap_t

def get_device():
        if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
                print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
                sys.exit(1)
        ## Print the list
        i=0
        try:
                d=alldevs.contents
        except:
                print ("Error in pcap_findalldevs: %s" % errbuf.value)
                print ("Maybe you need admin privilege?\n")
                sys.exit(1)
        while d:
                i=i+1
                print("%d. %s" % (i, d.name))
                if (d.description):
                        print (" (%s)\n" % (d.description))
                else:
                        print (" (No description available)\n")
                if d.next:
                        d=d.next.contents
                else:
                        d=False

        if (i==0):
                print ("\nNo interfaces found! Make sure WinPcap is installed.\n")
                sys.exit(-1)
        print ("Enter the interface number (1-%d):" % (i))
        inum= raw_input('--> ')
        if inum in string.digits:
            inum=int(inum)
        else:
            inum=0
        if ((inum < 1) | (inum > i)):
            print ("\nInterface number out of range.\n")
            ## Free the device list
            pcap_freealldevs(alldevs)
            sys.exit(-1)
        ## Jump to the selected adapter
        d=alldevs
        for i in range(0,inum-1):
            d=d.contents.next

        d = d.contents
        return d
