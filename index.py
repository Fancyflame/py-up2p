#                                                                                                           
from protocol import *
from socket import *
from time import sleep
import threading as th
import random
import math
#import re
#import traceback
from asyncevent import *

class up2pSocketErr(Exception):
    pass
class up2pRequestErr(Exception):
    pass

def launchTh(func,*args,daemon=True):
    wk=th.Thread(target=func,daemon=daemon,args=args)
    wk.start()
    #print(wk.name)
    """if re.search(r"3|4|6",wk.name)!=None:
        traceback.print_stack()"""
    return wk

class up2psocket(event_manager):
    _addr=None #服务器地址
    died=False
    outerAddr=None #服务器没有
    natlvl=None #服务器没有
    
    def __init__(self,address=("",0),accept=lambda self:None):
        self._s=socket(type=SOCK_DGRAM)
        self._addr=address
        self.accept=accept
        super().__init__()
        
        def recvp():
            try:
                by,ad=self._s.recvfrom(1024,0)
            except OSError:
                self.close()
                raise StopLoop()
            try:
                x=up2pproto(by)
                self.trigger("data",x,ad)
            except:
                pass
        self.loop(recvp)
    
    def sendp(self,proto,address=None):
        """发送up2p协议"""
        if address==None:address=self._addr
        if type(proto)!=up2pproto:
            proto=up2pproto(proto)
        """addr=(
            address[0] if address[0] else "127.0.0.1",
            address[1] if address[1] else 5557
        )"""
        self._s.sendto(proto.toBytes(),address)
        #if proto.i("method")!="handshake":print(proto.i("method"))
    
    def getRemoteInfo(self):
        #获取外部地址信息以及nat类型
        self.sendp({
            "method":"getouteraddr",
        })
        p=self.waitfor("data")[0]
        self.outerAddr=p.i("outeraddress")
        if self.natlvl!=None:return
        self.sendp({
            "method":"getouteraddr"
        },(self._addr[0],p.i("natport")))
        p=self.waitfor("data")[0]
        self.natlvl=0 if self.outerAddr[1]==p.i("outeraddress")[1] else 1
    
    def close(self):
        if self.died:return
        self._s.close()
        self.died=True
        self.trigger("close")
    
    #方法需重写
    def accept(self):
        pass

class client(up2psocket):
    _peer=None #连接端
    def run(self,destination):
        self._s.bind(("",0))
        self.getRemoteInfo()
        self._peer=destination
    
    def punching(self,tryTimes=50):
        def dri():
            destination=self._peer
            #请求连接
            CONN_PACK=up2pproto({
                "method":"connect",
                "destination":destination,
                "natlvl":self.natlvl,
                "scanrange":tryTimes,
                "ack":False
            })
            self.sendp(CONN_PACK)
            #因为内网穿透需要快速，所以请求对方地址
            #和穿透一定要在最后
            
            #主动响应。指后面发包过程中，数据包发往小范围端口
            #如果是False则为“被阻拦”方，往随机端口发包
            #positive=False
            #接收远程主机的连接
            while True:
                p=self.waitfor("data")[0]
                m=p.i("method")
                #来这么一出是防止恶意refuse
                if m=="refuseconnect" and p.i("from")==destination:
                    raise up2pRequestErr("Connect refused by remote host")
                elif m=="response" and p.i("ok")==False:
                    raise up2pRequestErr(p.i("reason"))
                elif m=="connect":
                    print("收到")
                    raddr=p.i("from")
                    rnat=p.i("natlvl")
                    if not p.i("ack"):
                        #如果不是确认包，那就发送确认包
                        #一般是由host的client发送无ack包
                        pack=CONN_PACK.copy({
                            "ack":True,
                            "destination":raddr
                        })
                        self.sendp(pack)
                        #先收到数据包的为主动，约定而已
                        #positive=True
                        sleep(0.01) #等对方收到
                    break
            
            #开始打洞！
            connected=False #打洞地址
            #检测是否连上
            def ln(p,ad):
                nonlocal connected
                if p.i("method")=="handshake" and ad[0]==raddr[0]:
                    connected=(p,ad)
                    self.off("data",ln)
            self.on("data",ln)
            ports=(p.i("scanrange")//2+1,)*tryTimes
            #sorted(range(-tryTimes,tryTimes+1),key=lambda n:abs(n),reverse=True):
            #主动发包{
            for i in ports:
                if connected:
                    break
                #如果对方nat是0，就直接往目标端口发包
                if rnat==0:ra=raddr
                else:
                    rnd=i+raddr[1]
                    print(rnd)
                    rnd=0xffff if rnd>0xffff else rnd
                    ra=(raddr[0],rnd)
                
                for ii in range(2):
                    self.sendp({
                        "method":"handshake",
                        "ack":False
                    },ra)
                    sleep(0.05) #稍微间隔一下，不然被运营商ban了可就不妙了
            else:
                def timer():
                    nonlocal connected
                    if not connected:
                        connected="timeout"
                th.Timer(2,timer)
                while True:
                    if connected:break
                    sleep(0.02)
            
            if connected=="timeout":
                self.trigger("error",up2pRequestError(
                    "Cannot get through the nat, please try again"))
                return
            p,ad=connected
            if p.i("ack")==False:
                #需要给予对方确认
                self.sendp({
                    "method":"handshake",
                    "ack":True
                })
            self.peer=connected
            self.trigger("connect")
        self.add_thread(dri)

class host(up2psocket):
    _timer_ping=None #心跳协程
    domain=None
    def run(self,domain=None):
        self._s.bind(("",0))
        self.getRemoteInfo()
        
        if domain:
            #请求域名
            self.sendp({
                "method":"domain",
                "domain":domain
            })
            p=self.waitfor("data")[0]
            if not p.i("ok"):
                raise up2pRequestErr("domain request error")
            self.domain=domain
        
        #启动心跳
        def heartbeat():
            while True:
                if self.died:break
                self.sendp({
                    "method":"heartbeat",
                    "domain":domain
                })
                sleep(10)
        if domain:self.add_thread(heartbeat)
    def listen(self):
        def loop(p,ad):
            m=p.i("method")
            if m=="connect":
                #有远程连接
                #取得用户同意（默认同意）
                if self.accept(p.i("from"))==False:return
                def foo():
                    c=client(self._addr)
                    rejected=False
                    #拒绝连接
                    def rej():
                        if rejected:
                            raise up2pSocketError("Only can reject one time")
                        self.sendp({
                            "method":"refuseconnect",
                            "destination":p.i("from")
                        })
                    self.trigger("client",c,p.i("from"),rej)
                self.add_thread(foo)
        self.on("data",loop)
    
    def close(self):
        if self.died:return
        if self._timer_ping:self._timer_ping.cancel()
        if self.domain:
            self.sendp({
                "method":"close",
                "domain":self.domain
            })
        super().close()

#中央处理服务器
class server(up2psocket):
    domains=None
    _kill_domains=None
    def run(self):
        self.domains=dict()
        self._kill_domains=dict()
        self._s.bind(self._addr)
        #ns是nat检测服务器
        self._ns=up2psocket((self._addr[0],0))
        self._ns._s.bind((self._addr[0],0))
        self.outerAddr=self._s.getsockname()
        
        #定时清理死亡主机
        def cleaner():
            sleep(15)
            for i in self._kill_domains.keys():
                del self.domains[i]
            self._kill_domains=self.domains.copy()
        self.loop(cleaner)
    
    def listen(self):
        #nat检测站的端口
        nattestport=self._ns._s.getsockname()[1]
        #nat检测服务器
        def ln(p,ad):
            n=self._ns
            m=p.i("method")
            if m=="getouteraddr":
                #获得外部地址
                n.sendp({
                    "ok":True,
                    "outeraddress":ad
                },ad)
            else:
                n.sendp({
                "ok":False,
                    "reason":"This is a nat-test server, it can only\
                        receive 'getouteraddr' method"
                },ad)
        self._ns.on("data",ln)
        
        def ln(p,ad):
            try:
                m=p.i("method")
            except:
                return
            #print("服务器："+m)
            
            des=None
            #获取地址（域名解析）
            def getDes():
                nonlocal des
                des=p.i("destination")
                if type(des)!=tuple:
                    try:
                        des=self.domains[des]
                        return True
                    except:
                        self.sendp({
                            "ok":False,
                            "reason":"Cannot find any host"+\
                                "match to the domain:"+des
                        },ad)
                        return False
                return True
            
            if m=="domain":
                #域名请求
                name=p.i("domain")
                if name in self.domains:
                    self.sendp({
                        "ok":False,
                        "reason":"This domain has been occupied"
                    },ad)
                else:
                    self.domains[name]=ad
                    self.sendp({
                        "ok":True
                    },ad)
            elif m=="getouteraddr":
                #获得外部地址
                self.sendp({
                    "ok":True,
                    "outeraddress":ad,
                    "natport":nattestport
                },ad)
            elif m=="heartbeat":
                #心跳包
                dom=p.i("domain")
                k=self._kill_domains
                if dom in k and (k[dom]==ad):
                    #需要验证地址是否正确
                    del k[dom]
            elif m=="connect":
                #请求连接
                if not getDes():return
                self.sendp({
                    "method":"connect",
                    "from":ad,
                    "ack":p.i("ack"),
                    "natlvl":p.i("natlvl"),
                    "scanrange":p.i("scanrange")
                },des)
            elif m=="refuseconnect":
                #拒绝连接
                if not getDes():return
                vl=self.domains.values()
                self.sendp({
                    "method":"refuseconnect"
                },des)
            elif m=="close":
                #删除域名映射
                d=p.i("domain")
                try:
                    del self.domains[d]
                    del self._kill_domains[d]
                except:
                    pass
            else:
                #未知方法
                if ad==self.outerAddr:
                    print("出现自循环！")
                    return
                self.sendp({
                    "ok":False,
                    "reason":"Unknown request method:"+m
                },ad)
        self.on("data",ln)
    
    def close(self):
        self._ns.close()
        super().close()

"""
def run(ty,*args):
    print("线程启动")
    k=ty(("",5557))
    def close():
        k.close()
        print("线程关闭")
    th.Timer(3,close).start()
    k.run(*args)
    #print(str(ty)+":"+str(k.outerAddr))
    if hasattr(k,"listen"):
        print("现在启动",ty)
        k.listen()
    else:
        k.once("connect",lambda:print("连接完成"))

run(server)
sleep(0.5)
run(host,"test")
sleep(0.5)
run(client,"test")
while True:
    try:
        sleep(10000)
    except KeyboardInterrupt:
        print("\nbye")
        th.Timer(0.5,lambda:print(th.enumerate())).start()
        break
"""