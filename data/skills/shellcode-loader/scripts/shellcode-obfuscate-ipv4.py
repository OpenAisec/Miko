#!/usr/bin/env python3
"""
Shellcode IPv4混淆工具
功能：将Shellcode伪装成IPv4地址数组
"""

import sys

def obfuscate_as_ipv4(shellcode):
    # 将Shellcode每4字节转换为一个IPv4地址
    ipv4_list = []
    for i in range(0, len(shellcode), 4):
        chunk = shellcode[i:i+4]
        if len(chunk) < 4:
            chunk = chunk.ljust(4, b'\x00')
        # 直接按字节顺序转换：chunk[0].chunk[1].chunk[2].chunk[3]
        ipv4 = f"{chunk[0]}.{chunk[1]}.{chunk[2]}.{chunk[3]}"
        ipv4_list.append(ipv4)
    return ipv4_list

def main():
    if len(sys.argv) != 2:
        print("Usage: python shellcode-obfuscate-ipv4.py <shellcode_file>")
        return

    with open(sys.argv[1], 'rb') as f:
        shellcode = f.read()

    ipv4_list = obfuscate_as_ipv4(shellcode)

    # 生成C语言数组格式
    c_array = "char* ipv4_array[] = {" + ",".join([f'"{ip}"' for ip in ipv4_list]) + "};"

    with open('shellcode_obfuscated_ipv4.c', 'w') as f:
        f.write(c_array)

    print(f"Shellcode obfuscated as IPv4 successfully! Total: {len(ipv4_list)} IPs")

if __name__ == "__main__":
    main()