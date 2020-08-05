#ug ug  gy gh ghu ghu                    ,  b  b  b b b b b kgc jg j vhv  vhjv h v hvh vh vvh vh  vhv h hv
from random import *
from time import sleep

itrp=0.1 #外部打扰概率
class nat:
    def __init__(self,rge=range(20000,50000)):
        """
        last:上一次取得的端口
        rge:端口取值范围
        """
        self.last=choice(rge)
        self._oft=self.last+randint(-20,20)
        #映射列表
        self._map=dict()
    def send(self,na,port):
        r=na.recv(self._oft,port)
        #内部端口对应外部端口
        self._map[str(self._oft)]=port
        self._oft+=1
        if random()<itrp:self._oft+=1
        return r
    def recv(self,sp,dp):
        m=self._map.get(str(dp))
        if m and m==sp:
            return True

def test():
    A=nat()
    B=nat()
    tt=45
    p1=(tt//2+1,)*tt
    p2=(tt//2+1,)*tt
    #print(p1,"\n\n",p2)
    suc=0
    for i in range(tt):
        if A.send(B,B.last+p1[i]):suc+=1
        if B.send(A,A.last+p2[i]):suc+=1
    return suc

total=2300
ok=0
for i in range(total):
    n=test()
    if n:ok+=1
    #print("第"+str(i+1)+"次实验中，成功了"+str(n)+"次")
print(str(total)+"次外部打扰概率设置为"+str(itrp*100)+ \
    "%的实验中，成功概率"+str(ok*100//total)+"%")