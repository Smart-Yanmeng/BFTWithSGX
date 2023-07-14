import leveldb
import hashlib


def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()


def _write(key, m):
    path = "./db"
    # print("key----"+key)
    db = leveldb.LevelDB(path)
    db.Put(key, m)
    # print(db.Get(key ).decode('utf-8'))


def _read(key):
    path = "./db"
    db = leveldb.LevelDB(path)
    m = db.Get(key)
    return m
