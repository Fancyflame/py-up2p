from index import *
import sys
from time import sleep

ar=sys.argv[1:]
ar+=("" for i in range(3-len(ar))) #填充长度至3
ty=ar[0] #类型
addr=("123.207.9.213",ar[1] if ar[1].isdigit() else \
    ar[2] if ar[2].isdigit() else 5557) #地址
if ty=="s":
    k=server(addr)
    k.run()
    k.listen()
    print("服务器已启动：",k.outerAddr)
elif ty=="h":
    k=host(addr)
    k.run(ar[1])
    print("外部地址为：",k.outerAddr)
    k.listen()
    def cnt(c,a):
        print("有客户端尝试连接",a)
        c.run(a)
        c.drill()
        def foo():
            print("对接成功")
            c.close()
        c.on("connect",foo)
    k.on("client",cnt)
elif ty=="c":
    k=client(addr)
    k.run(ar[1])
    print("外部地址为：",k.outerAddr)
    k.drill()
    def foo():
        print("对接成功")
        k.close()
    k.on("connect",foo)
else:
    print("未知类型：",ty)
    sys.exit()
while True:
    try:
        sleep(1000)
    except KeyboardInterrupt:
        print("退出测试")
        break