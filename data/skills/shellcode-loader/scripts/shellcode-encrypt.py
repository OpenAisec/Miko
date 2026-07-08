#!/usr/bin/env python3
"""
Shellcode加密工具
功能：使用自定义加密算法对Shellcode进行加密
"""

import sys

def custom_encrypt(shellcode, key):
    # 实现自定义加密算法
    encrypted = bytearray()
    for i, byte in enumerate(shellcode):
        encrypted_byte = (byte ^ key[i % len(key)])
        encrypted.append(encrypted_byte)
    return encrypted

def main():
    if len(sys.argv) != 3:
        print("Usage: python shellcode-encrypt.py <shellcode_file> <key>")
        return
    
    with open(sys.argv[1], 'rb') as f:
        shellcode = f.read()
    
    key = sys.argv[2].encode()
    encrypted = custom_encrypt(shellcode, key)
    
    with open('shellcode_encrypted.bin', 'wb') as f:
        f.write(encrypted)
    
    # 生成C语言数组格式
    c_array = "unsigned char shellcode[] = {" + ",".join([f"0x{byte:02x}" for byte in encrypted]) + "};"
    
    with open('shellcode_encrypted.c', 'w') as f:
        f.write(c_array)
    
    print("Shellcode encrypted successfully!")

if __name__ == "__main__":
    main()