"""
packet_analyzer.py — 游戏网络协议分析模板

功能:
- TCP/UDP 抓包
- 协议结构解析
- 包录制与回放
- 自动化客户端

依赖:
    pip install scapy struct
"""

import struct
import socket
import threading
import time
import json
from dataclasses import dataclass, field
from typing import Optional, Callable


@dataclass
class PacketHeader:
    """协议包头（根据实际游戏修改）"""
    length: int = 0
    packet_type: int = 0
    sequence: int = 0

    @staticmethod
    def parse(data: bytes) -> Optional['PacketHeader']:
        if len(data) < 8:
            return None
        # 小端序: 长度(4) + 类型(2) + 序列号(2)
        length, ptype, seq = struct.unpack('<IHH', data[:8])
        return PacketHeader(length=length, packet_type=ptype, sequence=seq)

    def pack(self, payload: bytes) -> bytes:
        return struct.pack('<IHH', len(payload), self.packet_type, self.sequence) + payload


class PacketAnalyzer:
    """协议分析器"""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.packets: list[dict] = []
        self.handlers: dict[int, Callable] = {}
        self.recording = False
        self.start_time = 0.0

    def register_handler(self, packet_type: int, handler: Callable):
        """注册包类型处理函数"""
        self.handlers[packet_type] = handler

    def start_record(self):
        """开始录制"""
        self.packets.clear()
        self.recording = True
        self.start_time = time.time()

    def stop_record(self):
        """停止录制"""
        self.recording = False

    def save(self, filename: str):
        """保存录制的包"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.packets, f, indent=2, ensure_ascii=False)

    def load(self, filename: str):
        """加载录制的包"""
        with open(filename, 'r', encoding='utf-8') as f:
            self.packets = json.load(f)

    def analyze(self, data: bytes, direction: str = 'C->S'):
        """分析一个数据包"""
        header = PacketHeader.parse(data)
        if not header:
            return

        payload = data[8:8 + header.length]
        pkt_info = {
            'time': time.time() - self.start_time if self.recording else 0,
            'direction': direction,
            'type': f'0x{header.packet_type:04X}',
            'length': header.length,
            'sequence': header.sequence,
            'payload_hex': payload.hex(),
            'payload_raw': list(payload),
        }

        if self.recording:
            self.packets.append(pkt_info)

        # 调用处理函数
        if header.packet_type in self.handlers:
            self.handlers[header.packet_type](header, payload)

        return pkt_info

    def print_packet(self, pkt: dict):
        """打印包信息"""
        print(f"[{pkt['direction']}] Type={pkt['type']} "
              f"Len={pkt['length']} Seq={pkt['sequence']}")
        print(f"  Payload: {pkt['payload_hex'][:64]}{'...' if len(pkt['payload_hex']) > 64 else ''}")

    def dump_packets(self):
        """打印所有录制的包"""
        for pkt in self.packets:
            self.print_packet(pkt)

    def stat_types(self):
        """统计包类型分布"""
        type_count: dict[str, int] = {}
        for pkt in self.packets:
            t = pkt['type']
            type_count[t] = type_count.get(t, 0) + 1
        for t, c in sorted(type_count.items(), key=lambda x: -x[1]):
            print(f"  {t}: {c} packets")


class ProxyServer:
    """TCP 中间人代理"""

    def __init__(self, listen_port: int, target_host: str, target_port: int):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.analyzer = PacketAnalyzer(target_host, target_port)
        self.running = False

    def _forward(self, src: socket.socket, dst: socket.socket, direction: str):
        """转发数据"""
        try:
            while self.running:
                data = src.recv(4096)
                if not data:
                    break
                self.analyzer.analyze(data, direction)
                dst.send(data)
        except ConnectionError:
            pass
        finally:
            src.close()
            dst.close()

    def _handle_client(self, client: socket.socket):
        """处理客户端连接"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.connect((self.target_host, self.target_port))
        except ConnectionError:
            client.close()
            return

        t1 = threading.Thread(target=self._forward, args=(client, server, 'C->S'))
        t2 = threading.Thread(target=self._forward, args=(server, client, 'S->C'))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()

    def start(self):
        """启动代理"""
        self.running = True
        self.analyzer.start_record()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.listen_port))
        sock.listen(5)
        sock.settimeout(1.0)

        print(f"[*] Proxy listening on :{self.listen_port}")
        print(f"[*] Forwarding to {self.target_host}:{self.target_port}")

        try:
            while self.running:
                try:
                    client, addr = sock.accept()
                    print(f"[+] Connection from {addr}")
                    threading.Thread(target=self._handle_client, args=(client,)).start()
                except socket.timeout:
                    pass
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            sock.close()
            self.analyzer.stop_record()


class ReplayClient:
    """协议回放客户端"""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_raw(self, data: bytes):
        if self.sock:
            self.sock.send(data)

    def recv_raw(self, size: int = 4096) -> bytes:
        if self.sock:
            return self.sock.recv(size)
        return b''

    def replay(self, packets_file: str, speed: float = 1.0):
        """回放录制的包"""
        with open(packets_file, 'r') as f:
            packets = json.load(f)

        self.connect()
        last_time = 0.0

        for pkt in packets:
            if pkt['direction'] != 'C->S':
                continue

            # 等待时间间隔
            wait = (pkt['time'] - last_time) / speed
            if wait > 0:
                time.sleep(wait)
            last_time = pkt['time']

            # 发送数据
            data = bytes.fromhex(pkt['payload_hex'])
            header = struct.pack('<IHH', len(data), int(pkt['type'], 16), pkt['sequence'])
            self.send_raw(header + data)
            print(f"[>] Sent {pkt['type']} ({len(data)} bytes)")

        self.disconnect()


# ========== 常见协议解析器 ==========

class GamePacketParser:
    """游戏协议解析示例（根据实际协议修改）"""

    @staticmethod
    def parse_login(payload: bytes) -> dict:
        """解析登录包"""
        if len(payload) < 64:
            return {}
        username = payload[:32].rstrip(b'\x00').decode('utf-8', errors='replace')
        password = payload[32:64].rstrip(b'\x00').decode('utf-8', errors='replace')
        return {'username': username, 'password': '***'}

    @staticmethod
    def parse_move(payload: bytes) -> dict:
        """解析移动包"""
        if len(payload) < 12:
            return {}
        x, y, z = struct.unpack('<fff', payload[:12])
        return {'x': x, 'y': y, 'z': z}

    @staticmethod
    def parse_chat(payload: bytes) -> dict:
        """解析聊天包"""
        if len(payload) < 2:
            return {}
        channel = payload[0]
        msg = payload[1:].rstrip(b'\x00').decode('utf-8', errors='replace')
        return {'channel': channel, 'message': msg}


# ========== 使用示例 ==========

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python packet_analyzer.py proxy <listen_port> <target_host> <target_port>")
        print("  python packet_analyzer.py replay <host> <port> <packets_file>")
        print("  python packet_analyzer.py analyze <packets_file>")
        sys.exit(0)

    mode = sys.argv[1]

    if mode == 'proxy':
        listen = int(sys.argv[2])
        thost = sys.argv[3]
        tport = int(sys.argv[4])
        proxy = ProxyServer(listen, thost, tport)
        proxy.start()

    elif mode == 'replay':
        host = sys.argv[2]
        port = int(sys.argv[3])
        pfile = sys.argv[4]
        client = ReplayClient(host, port)
        client.replay(pfile)

    elif mode == 'analyze':
        pfile = sys.argv[2]
        analyzer = PacketAnalyzer('', 0)
        analyzer.load(pfile)
        analyzer.dump_packets()
        print("\n--- Type Statistics ---")
        analyzer.stat_types()
