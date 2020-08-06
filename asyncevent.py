#
import threading as th
from time import sleep


def _event_manager__newth(func, args=(), daemon=True):
    wk = th.Thread(target=func, args=args, daemon=daemon)
    wk.start()
    return wk


class StopLoop(Exception):
    def __init__(self):
        super().__init__("Exit the loop. This error should be caught.")


class TimeoutError(Exception):
    def __init__(self):
        super().__init__("Wait timeout")


class event_manager:
    _listeners = None
    """
        {
            "event1":[func1,func2],
            "event2":[func3,func4,func5]
        }
    """
    _queue = None
    """
        [
            ("event1",args),
            ...
        ]
    """

    _worker = None  # 事件执行器
    _work = None  # 触发事件后唤醒worker
    _event = None  # 正在执行事件
    _joiners = None  # 等待加入工作循环的队列
    exit = False  # 是否已结束

    def __init__(self):
        """初始化"""
        self._queue = []
        self._joiners = []
        self._events = {}  # 塞 事件名:(事件对象,[监听器]) 键值对
        self._work = th.Event()

        # 执行监听函数
        def work():
            q = self._queue
            while True:
                # 等待触发事件
                self._work.wait()
                self._work.clear()

                # 要注意在worker工作时也有可能有新的
                # 线程或事件加入队列

                # 创建线程
                for i in self._joiners:
                    __newth(i[0], *i[1])
                self._joiners.clear()

                # 处理事件
                e = self._events
                for i in q:
                    # 队列里激活的事件
                    # 事件里没有监听者
                    if i[0] not in e:
                        continue
                    ev = e[i[0]]
                    for f in ev[1][:]:
                        # 每个监听函数
                        f(*i[1])
                    # 提示所有事件处理完毕
                    ev[0].set()
                    ev[0].clear()
                q.clear()

                if self.exit:
                    break

        self._worker = __newth(work)

    def on(self, name, func):
        """监听事件"""
        e = self._events
        if not name in e:
            e[name] = (th.Event(), [])
        e[name][1].append(func)

    def off(self, name, func):
        """取消监听事件"""
        e = self._events
        try:
            # 懒得给你判断，用try直接莽
            e[name][1].remove(func)
        except:
            pass

    def once(self, name, func):
        """监听一次事件"""

        def newf(*args):
            # event manager单次事件执行重写的方法
            func(*args)
            self.off(name, newf)

        self.on(name, newf)

    def add_thread(self, func, args=()):
        """添加线程执行任务"""
        # 不直接新建线程的原因是因为这样
        # 由_worker创建的线程就是_worker的
        # 守护线程，方便关闭
        self._joiners.append((func, args))
        self._work.set()

    def loop(self, func, evname=None):
        """添加自循环任务，并触发事件。请使用'raise StopLoop()'来退出循环"""
        # 如果func不会阻塞线程，那CPU就会被吃满
        def newf():
            while True:
                try:
                    res = func()
                except StopLoop:
                    break
                if evname != None:
                    self.trigger(evname, *res)

        self.add_thread(newf)

    def trigger(self, name, *args):
        """触发事件"""
        self._queue.append((name, args))
        self._work.set()

    def waitfor(self, name, timeout=None):
        """阻塞线程等待事件触发"""
        triggered = False  # 已触发事件
        a = ()

        def proxy(*args):
            nonlocal a
            nonlocal triggered
            a = args
            triggered = True

        self.once(name, proxy)
        while True:
            if not self._events[name][0].wait(timeout):
                raise TimeoutError()
            if triggered:
                return a

    def end_loop(self):
        """结束运行"""
        self.exit = True
        self._work.set()
