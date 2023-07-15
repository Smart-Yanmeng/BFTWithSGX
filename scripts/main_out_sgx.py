import struct
from ctypes import c_bool
import hashlib
import time
import socket
import struct
from io import BytesIO
from Server_receipt_sgx import SgxServer
from multiprocessing import Value as mpValue, Queue as mpQueue


def _hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()


def get_len(msg):
    buf = BytesIO()
    buf.write(struct.pack("<i", len(msg)))
    buf.write(msg)
    buf.seek(0)
    return buf.read()


def client_to_sgx(m):
    # FROM SERVER UNTRUSTED PART TO SERVER TRUSTED PART
    host = '127.0.0.1'
    port = 20000

    try:
        sk = socket.socket()
        sk.connect((host, port))
        tx = get_len(m)
        sk.sendall(tx)
        # data = sk.recv(1024)
        print("MESSAGE => ", m)
        print("SEND OK")
        sk.close()
    except Exception as e:
        print("Exception => ", e)
        client_to_sgx(m)


def main():
    # FROM OUTSIDE TO SERVER UNTRUSTED PART
    host = ''
    port = 10000
    n = 4
    f = 1
    sgx_q = mpQueue()
    sgx_put = sgx_q.put_nowait
    sgx_get = lambda: sgx_q.get(timeout=0.00001)
    sgx_ready = mpValue(c_bool, False)
    stop = mpValue(c_bool, False)

    sgx_server: SgxServer = SgxServer(port, host, sgx_put, sgx_get, sgx_ready, stop)
    sgx_server.start()

    sgx_cnt = dict()
    sgx_map = dict()
    st = dict()
    while sgx_ready:

        if not sgx_q.empty():
            tx = sgx_get()
            tx_h = hash(tx)

            if tx_h not in st:
                st[tx_h] = False

            if st[tx_h]:
                sgx_cnt[tx_h] = sgx_cnt[tx_h] + 1
                if sgx_cnt[tx_h] == n:
                    del sgx_cnt[tx_h]
                    del st[tx_h]
                continue

            if tx_h not in sgx_map:
                sgx_map[tx_h] = tx

            if tx_h not in sgx_cnt:
                sgx_cnt[tx_h] = 1
            else:
                sgx_cnt[tx_h] = sgx_cnt[tx_h] + 1
                if sgx_cnt[tx_h] >= f + 1:
                    _tx = sgx_map[tx_h]
                    del sgx_map[tx_h]
                    client_to_sgx(_tx)
                    st[tx_h] = True
        else:
            time.sleep(1)
            continue

    sgx_server.terminate()
    sgx_server.join()


if __name__ == '__main__':
    main()
