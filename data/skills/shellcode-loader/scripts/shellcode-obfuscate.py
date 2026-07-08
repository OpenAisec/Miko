#!/usr/bin/env python3
"""
Shellcode混淆工具
功能：将Shellcode伪装成UUID、IPv4/IPv6地址等格式
"""

import sys
import uuid

def obfuscate_as_uuid(shellcode):
    # 将Shellcode伪装成UUID数组
    uuids = []
    for i in range(0, len(shellcode), 16):
        chunk = shellcode[i:i+16]
        if len(chunk) < 16:
            chunk = chunk.ljust(16, b'\x00')
        uuid_str = str(uuid.UUID(bytes=chunk))
        uuids.append(uuid_str)
    return uuids

def main():
    if len(sys.argv) != 2:
        print("Usage: python shellcode-obfuscate.py <shellcode_file>")
        return
    
    with open(sys.argv[1], 'rb') as f:
        shellcode = f.read()
    
    uuids = obfuscate_as_uuid(shellcode)
    
    # 生成C语言数组格式
    c_array = "char* uuid_array[] = {" + ",".join([f'"{uuid}"' for uuid in uuids]) + "};"
    
    with open('shellcode_obfuscated.c', 'w') as f:
        f.write(c_array)
    
    print("Shellcode obfuscated successfully!")

if __name__ == "__main__":
    main()