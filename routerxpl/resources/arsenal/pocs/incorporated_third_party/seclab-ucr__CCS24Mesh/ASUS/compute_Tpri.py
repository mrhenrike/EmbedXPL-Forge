import hashlib
import os
import signal
from multiprocessing import Pool

_MAC = '04:42:1A:B4:C1:B0'
_TIMESTAMP = 0x66fc7ac9
_HASH = bytes.fromhex('03ed8ed751eb5131036a14701034380c')
group_id_pre_hash = hashlib.md5((_MAC + "_").encode())
timestamp_pre_hash = (_TIMESTAMP << 96) + (_TIMESTAMP << 64) + (_TIMESTAMP << 32) + _TIMESTAMP

def check(number):
    number_str = str(number)
    group_id = group_id_pre_hash.copy()
    group_id.update(number_str.encode())
    hash_result = (int.from_bytes(group_id.digest(), 'big') & timestamp_pre_hash).to_bytes(16, 'big')
    hash_result = hashlib.sha256(hash_result).digest()[0:16]
    if hash_result == _HASH:
        print('found:', number_str)
        os.kill(os.getppid(), signal.SIGTERM)

if __name__ == '__main__':
    with Pool(os.cpu_count()) as p:
        signal.signal(signal.SIGTERM, lambda sig, _: exit(0))
        p.map(check, range(1600000000, 1800000000), chunksize=20000)