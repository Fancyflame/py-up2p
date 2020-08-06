                                                                                                                 
from itertools import islice
from collections.abc import Iterable
import struct

class up2pProtoErr(Exception):
    pass
_up2pproto__keys=(
    "method","ok","reason","domain","destination",
    "ping","outeraddress","from","natport","leapgap",
    "scanrange","identifier"
)
_up2pproto__vtypes=(
    "string","number","bool","addr","bytes"
)
_up2pproto__methods=(
    "response","domain","getouteraddr","heartbeat",
    "connect","refuseconnect","close","handshake"
)
_up2pproto__iden=bytes((0x40, 0x83, 0xf4, 0xdc))
class up2pproto:
    def __init__(self,buf=None):
        self._dict={}
        if not buf:return #不进行初始化
        
        if type(buf) is dict:
            #使用值初始化
            self.i(buf)
            return
        
        itr=iter(buf)
        if bytes(islice(itr,4))!=__iden:
            raise up2pProtoErr("Protocol header incorrect")
        while True:
            def g(l=None):
                if l==None:return next(itr)
                else:return bytes(islice(itr,l))
            ty=None
            try:
                ty=g() #名字标识码
            except:
                break
            
            #读取名字
            try:
                if ty>=0xe0:#大于0xe0的就是自定义名称
                    ty-=0xe0
                    name=str(g(ty+1),encoding="utf8")
                else:
                    name=__keys[ty]
            except:raise up2pProtoErr("read unknown name:"+str(ty))
            
            #读取类型
            vty=g()
            try:
                x=__vtypes[vty]
            except:raise up2pProtoErr("read unknown value type:"+str(vty))
            
            #读取值
            if   x=="string":
                leng=g()
                value=str(g(leng),encoding="utf8")
            elif x=="number":
                #采用int型
                value=struct.unpack("i",g(4))[0]
            elif x=="bool":
                #仅当byte为1时取True其余都是False
                value=g()==1
            elif x=="addr":
                ip=".".join(map(lambda x:str(x),g(4)))
                port=int.from_bytes(g(2),"big")
                value=(ip,port)
            elif x=="bytes":
                leng=g()
                value=g(leng)
            
            #还原方法值
            if name=="method":
                value=__methods[value[0]]
            self._dict[name]=value
    
    def i(self,key,v=None,delete=False):
        if type(key) is dict:
            #如果传入的key是一个dict对象则遍历
            for k,v in key.items():
                self.i(k,v,delete=delete)
            return
        elif isinstance(key,Iterable) and type(key) is not str:
            for v in key:
                self.i(v,delete=delete)
            return
        
        if (not key in self._dict) and v==None:raise up2pProtoErr("key not found :"+str(key))
        if delete:
            del self._dict[key]
            return
        if v!=None:self._dict[key]=v
        if key=="ok":
            #响应文自动添加方法
            self.i("method","response")
        return self._dict[key]
    
    def has(self,key):
        return key in self._dict
    
    def toBytes(self):
        b=bytearray()
        b+=__iden
        for i,v in self._dict.items():
            #写入名称
            if i in __keys:
                b.append(__keys.index(i))
            else:
                #如果不是模板名称，则用自定义名称
                if not (0<len(i)<=32 and i.isidentifier()):
                    raise up2pProtoErr("the length of the key"+
                        "must be >0 and <=32, and the key must be a identifier")
                b.append(0xe0+len(i)-1)
                b+=bytes(i,"utf8")
                
            #压缩方法值
            if i=="method":
                if not v in __methods:
                    raise up2pProtoErr("invalid method value:"+str(v))
                v=bytes((__methods.index(v),))
            
            #写入类型和值
            if  type(v) is int or type(v) is float:
                b.append(__vtypes.index("number"))
                v=int(v)
                b+=struct.pack("i",v)
            elif type(v) is bool:
                b.append(__vtypes.index("bool"))
                b.append(1 if v else 0)
            elif type(v) is tuple and len(v)==2:
                b.append(__vtypes.index("addr"))
                ip=bytes(map(lambda x:int(x),v[0].split(".")))
                port=v[1].to_bytes(2,"big")
                b+=ip+port
            elif type(v) is str:
                b.append(__vtypes.index("string"))
                byt=bytes(v,"utf8")
                leng=len(byt)
                if leng>0xff:raise up2pProtoErr("length of bytes of string must less than 256")
                b.append(leng)
                b+=byt
            elif type(v) is bytes:
                b.append(__vtypes.index("bytes"))
                leng=len(v)
                if leng>0xff:raise up2pProtoErr("length of bytes must less than 256")
                b.append(leng)
                b+=v
        return b
    def copy(self,upd=None):
        """复制当前对象并选择覆盖副本"""
        p=up2pproto()
        p._dict=self._dict.copy()
        if upd!=None:
            p.i(upd)
        return p
"""
v=up2pproto()
v.i({
    "method":"get",
    "hippo":b"hippo",
    "sum":92,
    "address":("192.168.1.14",1234),
    "req":"Hello!I am testing.",
    "bool":True
})
v.i("address",("122.1.1.1",65533))
r=list(v.toBytes())
print(r)
r=up2pproto(r)
print(r._dict)
"""