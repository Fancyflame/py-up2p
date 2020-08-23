from scapy.all import *
from asyncevent import *
from time import sleep

pk=IP(
    src="54.65.76.87",dst="112.49.210.119"
)/UDP()
send(pk,inter=1)
ev=event_manager()
sniff(filter="udp",
    prn=lambda x:x.sprintf("{IP:%IP.src%-> %IP.dst%}",
    )