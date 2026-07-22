# 主机平台特化 (Platform Console)

## 概述

主机游戏逆向的难度较高，因为：
- 系统封闭，需要自制系统或漏洞才能运行自定义代码
- 硬件架构特殊（Cell、ARM 等）
- 有完善的加密和签名机制

## PlayStation

### PS4/PS5

```
前提条件:
- 需要特定固件版本的漏洞
- 安装自制系统 (HEN / Mira)

工具:
- IDA Pro (支持 MIPS/ARM 架构)
- PS4 SDK (自制)
- Apollo Save Tool — 存档编辑
- PS4 Cheater — 内存搜索

存档修改:
1. 导出存档到 USB
2. 用 Apollo 或 Save Wizard 解密
3. 修改存档数据
4. 重新加密并导入
```

## Xbox

### Xbox One/Series

```
开发模式:
- Xbox 支持开发者模式，可以侧载应用
- 需要开发者账号 ($19/年)

逆向难度:
- 系统安全性较高
- 漏洞较少
- 主要通过存档修改或网络协议分析
```

## Nintendo Switch

### Switch 逆向

```
前提条件:
- 需要早期固件的硬件漏洞 (RCM)
- 或软破漏洞

工具:
- Atmosphere — 自制系统
- EdiZon — 内存编辑和存档管理
- Switch Toolbox — 资源文件分析
- nxDumpTool — 游戏 dump

内存修改:
1. 进入 RCM 模式
2. 注入 Atmosphere payload
3. 运行游戏
4. 使用 EdiZon 搜索和修改内存

存档修改:
1. 使用 Checkpoint 导出存档
2. 分析存档格式
3. 修改数据
4. 导入存档
```

## 通用存档修改

### 存档解密

```python
# 通用存档分析流程
def analyze_save(file_path):
    """分析存档文件"""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # 1. 检查文件头
    magic = data[:4]
    print(f"Magic: {magic}")
    
    # 2. 检查是否加密
    entropy = calculate_entropy(data)
    if entropy > 7.5:
        print("文件可能是加密的")
    
    # 3. 搜索已知模式
    # 金币、等级、经验值等
    
    # 4. 尝试常见加密
    # XOR, AES, Blowfish 等
```

### 通用内存搜索

```
主机内存搜索思路:
1. 使用自制系统的内存查看器
2. 搜索已知值（类似 CE 的精确搜索）
3. 分析数据结构
4. 修改并验证
```

## 云游戏逆向

### 云游戏特点

```
云游戏的特殊性:
- 游戏运行在服务器，只有视频流传输到客户端
- 无法直接修改游戏内存
- 只能分析视频流和输入协议

可做的:
1. 分析视频流协议（通常是 WebRTC 或自定义协议）
2. 分析输入协议（键鼠/手柄映射）
3. 图像识别 + 自动化输入
4. 视频流解码和分析
```

## 工具汇总

```
通用工具:
- IDA Pro — 多架构反汇编
- Ghidra — 免费，支持多架构
- HxD — 十六进制编辑器
- Cheat Engine — 内存搜索（PC 和模拟器）

主机专用:
- PS4: PS4 Cheater, Apollo Save Tool
- Switch: EdiZon, Checkpoint, Switch Toolbox
- Xbox: 有限的工具支持

模拟器:
- RPCS3 (PS3)
- Yuzu/Ryujinx (Switch)
- Xenia (Xbox 360)
- 模拟器上可以使用 PC 的逆向工具
```
