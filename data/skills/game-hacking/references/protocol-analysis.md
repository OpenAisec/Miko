# 协议分析详解 (Protocol Analysis)

## 目录

1. [协议分析概述](#协议分析概述)
2. [抓包工具链](#抓包工具链)
3. [协议结构逆向](#协议结构逆向)
4. [加密与压缩分析](#加密与压缩分析)
5. [协议重放与伪造](#协议重放与伪造)
6. [实战案例](#实战案例)

---

## 协议分析概述

游戏协议是客户端与服务器之间的通信语言。分析协议可以：

- 理解游戏的数据交互方式
- 重放/伪造特定操作（如自动购买、自动战斗）
- 分析服务器权威性（判断哪些逻辑在服务端校验）
- 开发自定义客户端或机器人

### 协议分类

| 类型 | 特征 | 常见游戏 |
|------|------|----------|
| TCP 长连接 | 稳定、有序、有包头 | 大部分 MMORPG |
| UDP | 快速、无序、可能丢包 | FPS、MOBA |
| HTTP/HTTPS | 请求-响应模式 | 手游、页游 |
| WebSocket | 全双工、实时 | 部分 H5 游戏 |
| 自定义协议 | 混合 TCP+UDP | 大型端游 |

---

## 抓包工具链

### 通用抓包

```bash
# Wireshark — 底层网络抓包
# 1. 选择网卡开始捕获
# 2. 过滤游戏端口: tcp.port == 12345
# 3. 右键 Follow TCP Stream 查看完整会话

# 命令行抓包 (tshark)
tshark -i "Ethernet" -f "tcp port 12345" -w game_capture.pcap
```

### HTTP/HTTPS 代理

```bash
# mitmproxy — HTTP/HTTPS 中间人代理
# 安装
pip install mitmproxy

# 启动代理
mitmproxy --listen-port 8080

# 配置游戏使用代理（系统代理或修改配置文件）
# 安装 mitmproxy CA 证书以解密 HTTPS

# mitmproxy 脚本自动化
cat > addon.py << 'EOF'
from mitmproxy import http

def response(flow: http.HTTPFlow):
    if "api.game.com" in flow.request.pretty_host:
        print(f"[{flow.request.method}] {flow.request.pretty_url}")
        print(f"Request: {flow.request.text[:200]}")
        print(f"Response: {flow.response.text[:200]}")
        print("---")

def request(flow: http.HTTPFlow):
    if "api.game.com" in flow.request.pretty_host:
        # 可以修改请求
        # flow.request.text = flow.request.text.replace("old", "new")
        pass
EOF

mitmproxy -s addon.py --listen-port 8080
```

### TCP/UDP 直接抓包

```bash
# Fiddler — Windows GUI 代理工具
# 适合 HTTP/HTTPS 游戏

# 自定义代理脚本 (Python)
# 拦截 TCP 连接
import socket
import threading

def handle_client(client_sock, target_host, target_port):
    """中间人代理"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((target_host, target_port))
    
    def forward(src, dst, name):
        while True:
            data = src.recv(4096)
            if not data:
                break
            print(f"[{name}] {data.hex()}")
            dst.send(data)
    
    t1 = threading.Thread(target=forward, args=(client_sock, server_sock, "C->S"))
    t2 = threading.Thread(target=forward, args=(server_sock, client_sock, "S->C"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
```

### 手游抓包

```bash
# Android: 使用 adb + mitmproxy
# 1. 设置手机代理指向 PC 的 mitmproxy
# 2. 安装 CA 证书到系统证书目录

# 如果 app 使用证书固定 (Certificate Pinning):
# 需要用 Frida 绕过
frida -U -f com.game.package -l bypass_ssl.js

# bypass_ssl.js 内容示例
Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustManager.$new()], null);
});
```

---

## 协议结构逆向

### 包头分析

典型的 TCP 游戏协议包结构：

```
+----------+----------+----------+----------+
| 包长度    | 包类型    | 序列号    | 校验和    |
| 2-4 bytes| 2 bytes  | 2-4 bytes| 4 bytes  |
+----------+----------+----------+----------+
|            包体 (Payload)                  |
|            变长                            |
+-------------------------------------------+
```

### 分析步骤

```
1. 抓取大量包，观察大小规律
2. 固定大小的包 → 可能是心跳包或简单指令
3. 变长包 → 分析长度字段的位置和编码方式
4. 比对同一操作（如多次登录）的包差异
5. 尝试不同的数据类型解读（int16/int32/float/string）
```

### 协议结构识别

```python
import struct

def parse_packet_header(data):
    """解析包头"""
    if len(data) < 8:
        return None
    
    # 尝试不同的包头格式
    # 格式1: [长度(4)] [类型(2)] [保留(2)]
    pkt_len = struct.unpack('<I', data[:4])[0]
    pkt_type = struct.unpack('<H', data[4:6])[0]
    
    # 格式2: [类型(2)] [长度(2)] [序列号(4)]
    # pkt_type = struct.unpack('<H', data[:2])[0]
    # pkt_len = struct.unpack('<H', data[2:4])[0]
    
    return {
        'length': pkt_len,
        'type': pkt_type,
        'payload': data[8:pkt_len+8]
    }

def analyze_packet_types(captured_packets):
    """统计包类型分布"""
    type_count = {}
    for pkt in captured_packets:
        header = parse_packet_header(pkt)
        if header:
            t = header['type']
            type_count[t] = type_count.get(t, 0) + 1
    
    # 按频率排序
    for t, count in sorted(type_count.items(), key=lambda x: -x[1]):
        print(f"Type 0x{t:04X}: {count} packets")
```

---

## 加密与压缩分析

### 常见加密方式

```
1. XOR 加密 — 最简单，密钥通常是固定的或可推导的
2. AES/DES — 标准对称加密，密钥可能硬编码在客户端
3. 自定义算法 — 需要逆向分析具体实现
4. SSL/TLS — HTTPS 游戏使用，需要中间人解密
```

### XOR 解密

```python
def xor_decrypt(data, key):
    """XOR 解密"""
    if isinstance(key, int):
        key = bytes([key])
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# 自动检测 XOR 密钥
def find_xor_key(encrypted_data, known_plaintext):
    """已知明文攻击，推导 XOR 密钥"""
    key_len = len(known_plaintext)
    key = bytes([encrypted_data[i] ^ known_plaintext[i] for i in range(key_len)])
    return key

# 示例：已知登录包的用户名字段
# encrypted = b'\x4a\x2f\x3c\x55...'
# known = b'user'  # 已知明文
# key = find_xor_key(encrypted, known)
```

### 逆向加密函数

```
1. 在 IDA 中搜索加密相关的字符串（如 "AES"、"DES"、"encrypt"）
2. 找到加密函数后分析算法和密钥
3. 如果是标准算法，提取密钥即可
4. 如果是自定义算法，需要完整还原实现
```

---

## 协议重放与伪造

### 协议重放

```python
import socket
import time

class GameClient:
    """模拟游戏客户端"""
    
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
    
    def send_packet(self, pkt_type, payload):
        """发送数据包"""
        header = struct.pack('<IH', len(payload), pkt_type)
        self.sock.send(header + payload)
    
    def recv_packet(self):
        """接收数据包"""
        header = self.sock.recv(8)
        if len(header) < 8:
            return None
        pkt_len, pkt_type = struct.unpack('<IH', header)
        payload = self.sock.recv(pkt_len)
        return {'type': pkt_type, 'payload': payload}
    
    def login(self, username, password):
        """模拟登录"""
        payload = struct.pack('<32s32s', 
                              username.encode().ljust(32, b'\x00'),
                              password.encode().ljust(32, b'\x00'))
        self.send_packet(0x0001, payload)
        return self.recv_packet()
    
    def move(self, x, y, z):
        """模拟移动"""
        payload = struct.pack('<fff', x, y, z)
        self.send_packet(0x0010, payload)
    
    def attack(self, target_id):
        """模拟攻击"""
        payload = struct.pack('<I', target_id)
        self.send_packet(0x0020, payload)

# 使用示例
client = GameClient("127.0.0.1", 12345)
client.login("player1", "password123")
client.move(100.0, 0.0, 200.0)
client.attack(0x12345)
```

### 包录制与回放

```python
import json
import time

class PacketRecorder:
    """协议包录制与回放"""
    
    def __init__(self):
        self.packets = []
        self.recording = False
    
    def start_record(self):
        self.packets = []
        self.recording = True
        self.start_time = time.time()
    
    def record(self, direction, data):
        if self.recording:
            self.packets.append({
                'time': time.time() - self.start_time,
                'direction': direction,  # 'C->S' or 'S->C'
                'data': data.hex()
            })
    
    def stop_record(self):
        self.recording = False
    
    def save(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.packets, f, indent=2)
    
    def load(self, filename):
        with open(filename, 'r') as f:
            self.packets = json.load(f)
    
    def replay(self, client):
        """回放录制的包"""
        for i, pkt in enumerate(self.packets):
            if pkt['direction'] == 'C->S':
                # 等待对应的时间间隔
                if i > 0:
                    wait = pkt['time'] - self.packets[i-1]['time']
                    time.sleep(wait)
                client.sock.send(bytes.fromhex(pkt['data']))
```

---

## 实战案例

### 案例：分析 MMO 游戏的登录协议

```
1. 用 Wireshark 抓取登录过程的 TCP 流
2. 观察包结构:
   - 客户端发送: [04 00] [01 00] [用户名] [密码哈希]
   - 服务器响应: [04 00] [01 00] [00] [会话token]
3. 包头: 2字节长度 + 2字节类型
4. 登录类型 = 0x0001
5. 响应: 1字节状态码 + 会话token
6. 后续请求都需要带上会话token
```

### 案例：自动战斗脚本

```python
import time

class AutoBattle:
    """自动战斗机器人"""
    
    def __init__(self, client):
        self.client = client
        self.running = False
    
    def start(self):
        self.running = True
        while self.running:
            # 1. 检测周围怪物（通过协议获取）
            monsters = self.get_nearby_monsters()
            
            if monsters:
                # 2. 选择最近的怪物
                target = min(monsters, key=lambda m: m['distance'])
                
                # 3. 移动到怪物旁边
                self.client.move(target['x'], target['y'], target['z'])
                time.sleep(0.5)
                
                # 4. 攻击
                self.client.attack(target['id'])
                time.sleep(1.0)
                
                # 5. 检测是否需要回血
                hp = self.get_current_hp()
                if hp < 30:
                    self.use_potion()
            else:
                # 没有怪物，移动寻找
                self.client.move(random.randint(-100, 100), 0, 
                               random.randint(-100, 100))
                time.sleep(2.0)
```
