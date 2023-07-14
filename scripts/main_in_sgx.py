import hashlib
import socket
from unpack_struct import _unpack
from io import BytesIO
import struct


def _hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()


def _pack(key, m):
    buf = BytesIO()
    buf.write(struct.pack("<i", len(key)))
    buf.write(key)
    buf.write(struct.pack("<i", len(m)))
    buf.write(m)
    buf.seek(0)
    return buf.read()


def client_send(tx):
    # FROM SERVER TRUSTED PART TO SERVER UNTRUSTED PART
    host = 'localhost'
    port = 30000
    sk = socket.socket()
    sk.connect((host, port))

    sk.sendall(tx)
    # data = sk.recv(1024)
    print("SEND OK")
    sk.close()


def start_server():
    # FROM SERVER UNTRUSTED PART TO SERVER TRUSTED PART
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_address = ('localhost', 20000)
    server_socket.bind(server_address)

    server_socket.listen(1)
    print("SERVER STARTED, WAITING FOR CLIENT...")

    while True:
        client_socket, client_address = server_socket.accept()
        print("CLIENT OK, ADDRESS => ", client_address)

        handle_client(client_socket)

        client_socket.close()
        print("CLIENT CLOSED")


def handle_client(client_socket):
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        else:
            try:
                unpack_data = _unpack(data)
                if unpack_data == "":
                    print("DECRYPT FAILED")
                    break
                else:
                    key = _hash(unpack_data)
                    print("DECRYPT OK, DATA => ", data)
                    tx = _pack(key, data)
                    client_send(tx)

            except Exception as e:
                print("EXCEPTION => ", e)
                break


start_server()
