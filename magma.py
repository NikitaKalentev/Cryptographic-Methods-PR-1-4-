# magma.py – реализация шифра Магма (ГОСТ 28147-89 / ГОСТ Р 34.12-2015)

S_BOXES = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
]

def _sbox_replace(value):
    res = 0
    for i in range(8):
        nibble = (value >> (4 * i)) & 0xF
        res |= (S_BOXES[i][nibble] << (4 * i))
    return res

def _rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def _f(T, X):
    return _rotl(_sbox_replace((T + X) & 0xFFFFFFFF), 11)

def _key_schedule(key):
    if len(key) != 32:
        raise ValueError("Ключ Магмы должен быть 32 байта")
    K = [int.from_bytes(key[i*4:(i+1)*4], byteorder='little') for i in range(8)]
    round_keys = []
    for _ in range(4):
        round_keys.extend(K)
    return round_keys

def encrypt_block(block, key):
    if len(block) != 8:
        raise ValueError("Блок Магмы должен быть 8 байт")
    left = int.from_bytes(block[:4], byteorder='little')
    right = int.from_bytes(block[4:], byteorder='little')
    round_keys = _key_schedule(key)
    for i in range(32):
        f_val = _f(right, round_keys[i])
        left, right = right, left ^ f_val
    return right.to_bytes(4, byteorder='little') + left.to_bytes(4, byteorder='little')

def decrypt_block(block, key):
    if len(block) != 8:
        raise ValueError("Блок Магмы должен быть 8 байт")
    left = int.from_bytes(block[:4], byteorder='little')
    right = int.from_bytes(block[4:], byteorder='little')
    round_keys = _key_schedule(key)
    for i in range(31, -1, -1):
        f_val = _f(left, round_keys[i])
        left, right = right, left ^ f_val
    return right.to_bytes(4, byteorder='little') + left.to_bytes(4, byteorder='little')
