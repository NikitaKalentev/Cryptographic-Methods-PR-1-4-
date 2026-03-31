# main.py – точка входа, обработка аргументов

import argparse
import sys
import os
from utils import pad, unpad, hex_key_to_bytes
import magma
import kuznechik
import aes

BLOCK_SIZE = {
    'magma': 8,
    'kuznechik': 16,
    'aes': 16
}

def process_file(cipher, mode, input_file, output_file, key_bytes):
    block_size = BLOCK_SIZE[cipher]

    if cipher == 'magma':
        def encrypt_block(b): return magma.encrypt_block(b, key_bytes)
        def decrypt_block(b): return magma.decrypt_block(b, key_bytes)
    elif cipher == 'kuznechik':
        round_keys = kuznechik.key_schedule(key_bytes)
        if len(round_keys) != 10:
            raise RuntimeError(f"Ошибка: получено {len(round_keys)} раундовых ключей, ожидалось 10")
        def encrypt_block(b): return kuznechik.encrypt_block(b, round_keys)
        def decrypt_block(b): return kuznechik.decrypt_block(b, round_keys)
    elif cipher == 'aes':
        if len(key_bytes) != 16:
            raise ValueError("Для AES ключ должен быть 128 бит (16 байт)")
        def encrypt_block(b): return aes.encrypt_block(b, key_bytes)
        def decrypt_block(b): return aes.decrypt_block(b, key_bytes)
    else:
        raise ValueError("Неизвестный шифр")

    with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
        if mode == 'encrypt':
            data = fin.read()
            padded = pad(data, block_size)
            for i in range(0, len(padded), block_size):
                block = padded[i:i+block_size]
                enc_block = encrypt_block(block)
                fout.write(enc_block)
        else:  # decrypt
            data = fin.read()
            if len(data) % block_size != 0:
                raise ValueError("Шифртекст не кратен размеру блока")
            decrypted = b''
            for i in range(0, len(data), block_size):
                block = data[i:i+block_size]
                dec_block = decrypt_block(block)
                decrypted += dec_block
            fout.write(unpad(decrypted))

def main():
    parser = argparse.ArgumentParser(description='Симметричные шифры (Магма, Кузнечик, AES)')
    parser.add_argument('-c', '--cipher', required=True, choices=['magma', 'kuznechik', 'aes'],
                        help='Выбор шифра')
    parser.add_argument('-k', '--key', required=True, help='Ключ в шестнадцатеричном виде')
    parser.add_argument('-i', '--input', required=True, help='Входной файл')
    parser.add_argument('-o', '--output', required=True, help='Выходной файл')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_true', help='Шифрование')
    group.add_argument('-d', '--decrypt', action='store_true', help='Расшифрование')
    args = parser.parse_args()

    try:
        key = hex_key_to_bytes(args.key)
        if args.cipher == 'magma' and len(key) != 32:
            raise ValueError("Для Магмы ключ должен быть 32 байта")
        if args.cipher == 'kuznechik' and len(key) != 32:
            raise ValueError("Для Кузнечика ключ должен быть 32 байта")
        if args.cipher == 'aes' and len(key) != 16:
            raise ValueError("Для AES ключ должен быть 16 байт")
    except Exception as e:
        print(f"Ошибка ключа: {e}")
        sys.exit(1)

    if not os.path.exists(args.input):
        print(f"Файл {args.input} не найден")
        sys.exit(1)

    try:
        mode = 'encrypt' if args.encrypt else 'decrypt'
        process_file(args.cipher, mode, args.input, args.output, key)
        print("Операция выполнена!")
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
