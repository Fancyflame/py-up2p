from index import *
import sys
from time import sleep

ar=sys.argv[1:]
ar+=("" for i in range(3-len(ar))) #填充长度至3
ty=ar[0] #类型
IP="123.207.9.213" if 1 else "127.0.0.1"
addr=(IP,ar[1] if ar[1].isdigit() else \
    ar[2] if ar[2].isdigit() else 5557) #地址
if ty=="s":
    addr=("",addr[1])
    k=server(addr)
    k.run()
    k.listen()
    print("服务器已启动：",k.outerAddr)
elif ty=="h":
    k=host(addr)
    k.run(ar[1])
    print("外部地址为：",k.outerAddr,
        "端口跳跃：",k.leapgap)
    k.listen()
    def cnt(c,a,reject):
        print("有客户端尝试连接",a)
        c.run(a)
        c.punching()
        def foo():
            print("对接成功辣！")
            #c.close()
        c.on("connect",foo)
        c.on("error",lambda:print("等待超时"))
    k.on("client",cnt)
elif ty=="c":
    k=client(addr)
    k.run(ar[1])
    print("外部地址为：",k.outerAddr,
        "端口跳跃：",k.leapgap)
    k.punching()
    def foo():
        print("对接成功辣！")
        #k.close()
    k.on("connect",foo)
    k.on("error",lambda:print("等待超时"))
else:
    print("未知类型：",ty)
    sys.exit()
while True:
    try:
        sleep(1000)
    except KeyboardInterrupt:
        print("退出测试")
        break