import socket
from io import BytesIO
import struct
from _leveldb import _write


def _unpack(tx):
    buf = BytesIO(tx)

    key_len_bytes = buf.read(4)
    key_len, = struct.unpack("<i", key_len_bytes)
    key = buf.read(key_len)

    m_len_bytes = buf.read(4)
    m_len, = struct.unpack("<i", m_len_bytes)
    m = buf.read(m_len)

    return key, m


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('localhost', 30000)
    server_socket.bind(server_address)

    server_socket.listen(1)
    print("SERVER STARTED, WAITING FOR CLIENT...")

    while True:
        client_socket, client_address = server_socket.accept()
        print("CLIENT OK, ADDRESS => ", client_address)

        handle_client(client_socket)

        client_socket.close()


def handle_client(client_socket):
    data = b''
    while True:
        data += client_socket.recv(1024)
        if not data:
            break
        else:
            buf = BytesIO(data)
            size, = struct.unpack("<i", buf.read(4))
            tx = buf.read(size)
            if len(data) - 4 != size:
                continue
            try:
                key, m = _unpack(tx)
                _write(key, m)
                print("DATA HAS BEEN STORED, DATA => ", data)
            except Exception as e:
                print("Exception => ", e)
            break


start_server()
