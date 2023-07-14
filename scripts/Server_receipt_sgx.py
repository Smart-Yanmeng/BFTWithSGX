from gevent import monkey;

monkey.patch_all(thread=False)
from gevent.server import StreamServer
import pickle
from typing import Callable
import os
import logging
import traceback
from multiprocessing import Value as mpValue, Process


# Network node class: deal with socket communications
class SgxServer(Process):
    SEP = '\r\nSEP\r\nSEP\r\nSEP\r\n'.encode('utf-8')

    def __init__(self, port: int, my_ip: str, sgx_put: Callable,
                 sgx_get: Callable, server_ready: mpValue, stop: mpValue):

        self.sgx_put = sgx_put
        self.sgx_get = sgx_get
        self.ready = server_ready
        self.stop = stop
        self.ip = my_ip
        self.port = port
        super().__init__()

    def _listen_and_recv_forever(self):
        pid = os.getpid()
        print("receipt my IP is " + self.ip)

        def _handler(sock, address):
            # buf = b''

            tmp = b''
            try:
                while not self.stop.value:

                    tmp = sock.recv(200000)
                    while True:
                        if tmp == b'0':
                            break
                        if tmp != '' and tmp:
                            # print("王文卓发来数据")
                            self.sgx_put(tmp)  # sever_put
                            # tx = self.message_get()
                            # print("成功放入队列")

                        else:
                            raise ValueError
                        tmp = b''
                        if tmp == b'':
                            break
                    break
            except Exception as e:
                print(str((e, traceback.print_exc())))

        self.streamServer = StreamServer((self.ip, self.port), _handler)
        self.streamServer.serve_forever()

    def run(self):
        pid = os.getpid()
        # self.logger = self._set_server_logger(self.id)
        with self.ready.get_lock():
            self.ready.value = True
        self._listen_and_recv_forever()
