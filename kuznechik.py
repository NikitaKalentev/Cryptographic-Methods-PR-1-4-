# kuznechik.py – реализация шифра Кузнечик

PI = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 82, 170, 208, 26, 0, 65, 115, 137, 141, 217, 56, 103, 27, 248, 47, 75, 133, 146, 76, 113, 216, 89, 192, 109, 179, 107, 229, 140, 202, 136, 105, 151, 194, 38, 230, 48, 32, 247, 97, 130, 182, 37, 163, 172, 254, 209, 190, 98, 125, 149, 45, 167, 180, 184, 7, 96, 85, 73, 159, 64, 225, 226, 231, 30]

PI_INV = [0] * 256
for i, v in enumerate(PI):
    PI_INV[v] = i

L_COEFFS = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]
POLY = 0x1C3

def gf_mul_k(a, b):
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= (POLY >> 1) & 0xFF
        b >>= 1
    return res

def X(k, a):
    return bytes(x ^ y for x, y in zip(k, a))

def S(block):
    return bytes(PI[b] for b in block)

def S_inv(block):
    return bytes(PI_INV[b] for b in block)

def R(block):
    val = 0
    for coeff, byte in zip(L_COEFFS, block):
        val ^= gf_mul_k(coeff, byte)
    return bytes([val]) + block[:-1]

def L(block):
    for _ in range(16):
        block = R(block)
    return block

def R_inv(block):
    last = block[1:]
    a15 = block[0]
    vec = last + bytes([a15])
    new_byte = 0
    for coeff, byte in zip(L_COEFFS, vec):
        new_byte ^= gf_mul_k(coeff, byte)
    return last + bytes([new_byte])

def L_inv(block):
    for _ in range(16):
        block = R_inv(block)
    return block

def key_schedule(master_key):
    # Проверка длины PI
    if len(PI) != 256:
        raise RuntimeError(f"PI имеет длину {len(PI)}, ожидается 256")
    if len(L_COEFFS) != 16:
        raise RuntimeError(f"L_COEFFS имеет длину {len(L_COEFFS)}, ожидается 16")
    if len(master_key) != 32:
        raise ValueError("Ключ Кузнечика должен быть 32 байта")

    K = [master_key[:16], master_key[16:]]

    C = []
    for i in range(1, 33):
        v = bytes([i] + [0]*15)
        C.append(L(v))

    for i in range(1, 5):
        left, right = K[2*i-2], K[2*i-1]
        for j in range(1, 9):
            const = C[8*(i-1) + (j-1)]
            a1 = right
            a0 = left
            t = L(S(X(const, a1)))
            right, left = X(t, a0), a1
        K.append(left)
        K.append(right)

    return K[:10]

def encrypt_block(block, round_keys):
    if len(round_keys) != 10:
        raise ValueError("Должно быть 10 раундовых ключей")
    state = X(round_keys[0], block)
    for i in range(1, 10):
        state = S(state)
        state = L(state)
        state = X(round_keys[i], state)
    return state

def decrypt_block(block, round_keys):
    if len(round_keys) != 10:
        raise ValueError("Должно быть 10 раундовых ключей")
    state = X(round_keys[9], block)
    for i in range(8, -1, -1):
        state = L_inv(state)
        state = S_inv(state)
        state = X(round_keys[i], state)
    return state
