# 协议与接口逆向参考手册

## 一、Wireshark 过滤器速查

### 显示过滤器

```
# 基础过滤
ip.addr == 192.168.1.1          # IP 地址
tcp.port == 8080                # TCP 端口
udp.port == 5353                # UDP 端口
http.request.method == "POST"   # HTTP POST
dns.qry.name contains "example" # DNS 查询

# 协议过滤
websocket                       # WebSocket 流量
tls.handshake                   # TLS 握手
mqtt                            # MQTT 协议
modbus                          # Modbus 工业协议
protobuf                        # Protobuf

# 组合过滤
http && ip.dst == 10.0.0.1 && tcp.port == 443
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN 包
frame.len > 1000                # 大于 1000 字节的包
```

### 捕获过滤器（BPF）

```
host 192.168.1.1                # 指定主机
port 80                         # 指定端口
src net 10.0.0.0/8              # 源网段
tcp port 443 and host 10.0.0.1  # 组合
not arp and not icmp            # 排除协议
```

### 实用操作

```
# 跟踪 TCP/HTTP 流：右键 → Follow → TCP Stream
# 导出 HTTP 对象：File → Export Objects → HTTP
# 会话统计：Statistics → Conversations
# 协议分层：Statistics → Protocol Hierarchy
```

## 二、mitmproxy 脚本编程

```python
# addon_example.py
from mitmproxy import http, ctx

class LogAddon:
    def request(self, flow: http.HTTPFlow):
        ctx.log.info(f"[REQ] {flow.request.method} {flow.request.url}")
        # 修改请求头
        flow.request.headers["X-Custom"] = "injected"

    def response(self, flow: http.HTTPFlow):
        ctx.log.info(f"[RSP] {flow.response.status_code} {flow.request.url}")
        # 修改响应体
        if "application/json" in flow.response.headers.get("content-type", ""):
            ctx.log.info(f"    Body: {flow.response.text[:200]}")

    def websocket_message(self, flow: http.HTTPFlow):
        msg = flow.websocket.messages[-1]
        direction = "->" if msg.from_client else "<-"
        ctx.log.info(f"[WS] {direction} {msg.content[:100]}")

addons = [LogAddon()]
# 运行: mitmproxy -s addon_example.py -p 8080
```

## 三、TCP/UDP 协议分析

### tcpdump 常用命令

```bash
tcpdump -i eth0 -nn port 8080                    # 抓指定端口
tcpdump -i eth0 -nn -w capture.pcap tcp port 443  # 保存到文件
tcpdump -r capture.pcap -nn                        # 读取文件
tcpdump -i eth0 -nn 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'  # 匹配 GET 请求
```

### 协议结构识别模式

```
常见协议层次:
┌──────────┬──────────┬──────────────────────┐
│  Header  │  Length  │     Payload          │
│ (固定)    │ (变长)    │  (Length 指定)        │
└──────────┴──────────┴──────────────────────┘

长度字段模式:
1. 固定长度: 每个包都是 N 字节
2. TLV (Type-Length-Value): [1B type][2B length][NB value]
3. 分隔符: 以 \r\n 或 \0 分隔
4. 长度前缀: [4B 长度][数据]
```

### Python struct 解析

```python
import struct

# 大端序解析
header = data[:4]
msg_type, msg_len = struct.unpack('>HH', header)
payload = data[4:4+msg_len]

# 小端序
val = struct.unpack('<I', data[:4])[0]

# 常见格式: >I (大端32位), <H (小端16位), >Q (大端64位)
# 网络字节序通常为大端（Big Endian）
```

### 字节序检测技巧

```python
# 方法：发送已知值，观察字节排列
# 值 0x12345678
# 大端: 12 34 56 78
# 小端: 78 56 34 12
# 通常：网络协议用大端，x86 本地程序用小端
```

## 四、Scapy 协议重放

```python
from scapy.all import *

# 基础包构造
pkt = IP(dst="10.0.0.1") / TCP(dport=8080, flags="S")  # SYN
resp = sr1(pkt)  # 发送并等待一个响应

# 自定义协议层
class MyProto(Packet):
    name = "MyProto"
    fields_desc = [
        ShortField("msg_type", 0),
        ShortField("msg_len", 0),
        StrLenField("payload", "", length_from=lambda p: p.msg_len),
    ]

pkt = IP(dst="10.0.0.1") / TCP(dport=9000) / MyProto(msg_type=1, payload=b"hello")
send(pkt)

# 从 pcap 读取并重放
pkts = rdpackets("capture.pcap")
for pkt in pkts:
    if pkt.haslayer(TCP) and pkt[TCP].dport == 8080:
        send(pkt[IP])  # 重放

# Fuzzing
pkt = IP(dst="10.0.0.1") / TCP(dport=8080) / MyProto(payload=Fuzz())
send(pkt, count=100)
```

## 五、Protobuf 逆向

### 识别

```
特征: 字节流以 0x0a (field 1, wire type 2) 开头
varint 编码: 最高位为 1 表示后续字节属于同一值
field tag = (field_number << 3) | wire_type
wire_type: 0=varint, 1=64bit, 2=length-delimited, 5=32bit
```

### 解码

```bash
# protoc 原始解码（无需 .proto 文件）
echo "0a0368656c6c6f" | xxd -r -p | protoc --decode_raw

# blackboxprotobuf（Python，无需 .proto）
pip install blackboxprotobuf
python3 -c "
import blackboxprotobuf
data = bytes.fromhex('0a0368656c6c6f')
message, typedef = blackboxprotobuf.decode_message(data)
print(message)
print(typedef)
"

# protobuf-inspector
pip install protobuf-inspector
cat data.bin | protobuf_inspector
```

### Proto 文件还原

```python
# 用 blackboxprotobuf 生成 typedef 后手动还原为 .proto
import blackboxprotobuf
data = open('sample.bin', 'rb').read()
message, typedef = blackboxprotobuf.decode_message(data)
# typedef 是字段定义字典，转换为 .proto 格式
```

### gRPC 反射

```bash
# 使用 grpcurl 调用反射 API
grpcurl -plaintext localhost:50051 list          # 列出服务
grpcurl -plaintext localhost:50051 describe pkg.ServiceName  # 描述服务
grpcurl -plaintext -d '{"key":"value"}' localhost:50051 pkg.ServiceName/Method
```

## 六、序列化格式识别

| 格式 | 魔数/特征 | 识别方法 |
|------|----------|---------|
| Protobuf | `0x0a` 开头，varint 编码 | protoc --decode_raw |
| MessagePack | `0xc0-0xdf` 前缀 | `msgpack -b data.bin` |
| Thrift | `0x80` 或 `0x00` 开头 | TBinaryProtocol: 4B version + method |
| Avro | `Obj\x01` 魔数 | avro-tools |
| CBOR | major type 前 3 bit | cbor2 Python 库 |
| JSON | `{` 或 `[` 开头 | 直接可读 |

### MessagePack 解码

```python
import msgpack
with open('data.bin', 'rb') as f:
    obj = msgpack.unpack(f)
    print(obj)
```

### 自定义二进制格式

```python
import struct

def parse_custom(data):
    offset = 0
    results = []
    while offset < len(data):
        # 假设: [2B type][2B length][NB payload]
        if len(data) - offset < 4:
            break
        msg_type, msg_len = struct.unpack('>HH', data[offset:offset+4])
        offset += 4
        payload = data[offset:offset+msg_len]
        offset += msg_len
        results.append({'type': msg_type, 'payload': payload})
    return results
```

## 七、RPC 协议逆向

### gRPC

```bash
# gRPC over HTTP/2
# 识别: HTTP/2 帧，Content-Type: application/grpc
# 帧格式: [1B compressed][4B length][NB message]

# 反射
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 describe package.Service

# 无需反射时：抓包分析 protobuf 编码的请求/响应
```

### JSON-RPC 2.0

```json
// 请求
{"jsonrpc":"2.0","method":"getUser","params":{"id":1},"id":1}
// 响应
{"jsonrpc":"2.0","result":{"name":"test"},"id":1}
// 特征: 固定 jsonrpc 字段，method/params/id 结构
```

### IPC 机制

```bash
# Named Pipes (Windows)
# 特征: \\.\pipe\pipename
# 工具: Pipe Monitor, Process Monitor

# Unix Domain Sockets (Linux)
# 特征: /tmp/.X11-unix/X0 等 socket 文件
strace -e trace=connect -f target_program

# D-Bus (Linux)
dbus-monitor --session   # 监控会话总线
dbus-monitor --system    # 监控系统总线
busctl list              # 列出总线连接
```

## 八、蓝牙与 IoT

### BLE 分析

```bash
# nRF Connect (手机 App) - 扫描 BLE 设备
# Wireshark - 导入 BLE 抓包
# 关键: GATT Service UUID → Characteristic UUID → Read/Write/Notify

# BLE 特征码
# Service: 0x1800 (Generic Access), 0x1801 (Generic Attribute)
# 常见: 0x180A (Device Information), 0x180F (Battery)
```

### MQTT

```bash
# 订阅所有主题
mosquitto_sub -h broker.example.com -t '#' -v

# 发布消息
mosquitto_h -h broker.example.com -t 'test/topic' -m 'hello'

# 抓包分析: Wireshark MQTT dissector
# 关键: CONNECT/SUBSCRIBE/PUBLISH 包, topic, payload
```

### Modbus

```bash
# 功能码: 01=读线圈, 02=读离散输入, 03=读保持寄存器, 04=读输入寄存器
# 05=写单个线圈, 06=写单个寄存器

# Wireshark 过滤
modbus && ip.addr == 192.168.1.100

# Python Modbus 客户端
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient('192.168.1.100', port=502)
result = client.read_holding_registers(0, 10, slave=1)
print(result.registers)
```

## 九、协议文档化

### 字段表模板

```markdown
## 消息格式: LoginRequest (type=0x01)

| 偏移 | 长度 | 类型 | 字段名 | 说明 |
|------|------|------|--------|------|
| 0x00 | 2 | uint16 BE | msg_type | 消息类型 = 0x01 |
| 0x02 | 2 | uint16 BE | msg_len | 后续数据长度 |
| 0x04 | 4 | uint32 BE | user_id | 用户 ID |
| 0x08 | N | string | username | 用户名（UTF-8） |
| 0x08+N | 16 | bytes | token | 认证令牌 |
```

### Wireshark Lua Dissector 模板

```lua
-- myproto.lua
local myproto = Proto("myproto", "My Custom Protocol")

myproto.fields.msg_type = ProtoField.uint16("myproto.type", "Message Type", base.HEX)
myproto.fields.msg_len  = ProtoField.uint16("myproto.len", "Length", base.DEC)
myproto.fields.payload  = ProtoField.bytes("myproto.payload", "Payload")

function myproto.dissector(buf, pinfo, tree)
    pinfo.cols.protocol = "MYPROTO"
    local subtree = tree:add(myproto, buf())
    subtree:add(myproto.fields.msg_type, buf(0,2))
    subtree:add(myproto.fields.msg_len, buf(2,2))
    local len = buf(2,2):uint()
    subtree:add(myproto.fields.payload, buf(4, len))
end

-- 注册到 TCP 端口
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(9000, myproto)
-- 加载: wireshark -X lua_script:myproto.lua
```
