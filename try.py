from socket import *
from time import sleep

for ii in range(100):
    s = socket(type=SOCK_DGRAM)
    s.settimeout(3)
    s.bind(("", 0))
print("done")
while True:
    try:
        sleep(30)
    except:
        break
