import sys

def gf_mul(a, b, poly=0x11b):
    """Умножение в GF(2^8) с полиномом poly (по умолчанию для AES)"""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= poly
        b >>= 1
    return res

def pad(data, block_size):
    """PKCS#7 дополнение"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """Удаление PKCS#7"""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Некорректное дополнение")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Неверное дополнение")
    return data[:-pad_len]

def hex_key_to_bytes(key_hex):
    """Преобразование hex-строки в байты"""
    return bytes.fromhex(key_hex)
