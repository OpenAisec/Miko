# 最新逆向技术详解（2025-2026）

## DMA 硬件级内存读写

### 原理
通过 PCIe 接口直接读取系统内存，完全绕过操作系统和反外挂。

### 工具
- **PCILeech** — 开源 DMA 工具 https://github.com/ufrisk/pcileech
- **FPGA 自定义设备** — 完全定制化
- **硬件成本** — $300-500

### 优势
- 反外挂完全无法检测（硬件层面）
- 可以读取受保护的内存区域
- 不触发任何软件级监控

### 代码示例（PCILeech API）
```c
#include <pcileech.h>

// 读取游戏内存
uint64_t game_base = 0x7FF612340000;
uint32_t health = 0;
pcileech_memread(game_base + 0x1A3B5C, &health, sizeof(health));
```

## 虚拟化层攻击（Hypervisor）

### 原理
利用 CPU 的 VT-x 虚拟化技术，在 Ring -1 层（比内核更高权限）拦截游戏。

### EPT Hook
```
1. 创建虚拟机，将游戏运行在 VMX non-root 模式
2. 设置 EPT（Extended Page Table）映射
3. 当游戏访问被 Hook 的页面时，触发 VMExit
4. 在 VMExit 处理中执行自定义逻辑
5. 返回游戏继续执行
```

### 优势
- 比内核驱动更隐蔽（在驱动之上）
- 可以拦截任何内存访问
- 反外挂无法检测（需要同级权限才能发现）

### 参考项目
- **HyperBone** — 虚拟化框架
- **SimpleSvm** — AMD SVM 示例
- **hvpp** — 轻量级 hypervisor

## 直接系统调用（Direct Syscalls）

### 原理
Windows API 调用链：应用程序 → ntdll.dll → 内核
反外挂监控 ntdll.dll 的调用。

直接系统调用跳过 ntdll.dll，直接调用内核。

### 实现方式
```c
// 传统方式（被监控）
NtReadVirtualMemory(hProcess, addr, buf, size, NULL);

// 直接系统调用（不被监控）
__asm__ __volatile__(
    "mov rax, 0x3F\n"      // NtReadVirtualMemory 的系统调用号
    "mov rcx, hProcess\n"
    "mov rdx, addr\n"
    "mov r8, buf\n"
    "mov r9, size\n"
    "syscall\n"
);
```

### 工具
- **SysWhispers** — 自动生成系统调用代码 https://github.com/jthuraisamy/SysWhispers
- **HellsGate** — 运行时解析系统调用号
- **RecycledGate** — 从 ntdll 中复用系统调用指令

### 栈伪造（Stack Spoofing）
```
问题：反外挂检查调用栈，直接 syscall 的调用栈不正常
解决：伪造一个合法的调用栈，看起来像是正常 API 调用
工具：SilentMoonwalk、Stack Spoofing PoC
```

## 内核回调解除

### 原理
反外挂通过注册内核回调来监控系统事件：
- 进程创建/销毁
- 模块加载
- 对象句柄操作

解除这些回调可以绕过监控。

### 进程回调解除
```c
// 反外挂注册的回调
PsSetCreateProcessNotifyRoutine(callback, TRUE);

// 解除回调
// 1. 找到回调数组地址
// 2. 遍历数组，找到目标回调
// 3. 将其从数组中移除
PVOID* callback_array = GetCallbackArrayAddress();
for (int i = 0; i < MAX_CALLBACKS; i++) {
    if (callback_array[i] == target_callback) {
        callback_array[i] = NULL;
    }
}
```

### ObRegisterCallbacks 解除
```
反外挂用 ObRegisterCallbacks 监控句柄操作
解除方法：找到回调链表，断开目标节点
```

## 硬件指纹伪装（HWID Spoof）

### 检测项
| 项目 | 修改方式 |
|------|---------|
| 主板序列号 | 注册表修改 |
| 硬盘序列号 | VolumeID 工具 |
| MAC 地址 | 注册表修改 |
| CPU ID | 硬件级，不可修改 |
| GPU ID | 硬件级，不可修改 |
| TPM | 可以清除/重置 |
| Windows GUID | 注册表修改 |
| 显示器 EDID | 可修改 |

### 参考
https://github.com/RejiDev/game-hacking-guidelines/blob/master/techniques/hwid.md

## Windows 安全特性绕过

### VBS（Virtualization Based Security）
```
Windows 虚拟化安全，将关键安全功能放在隔离的虚拟机中
绕过方法：禁用 VBS、利用漏洞突破虚拟化边界
```

### HVCI（Hypervisor-protected Code Integrity）
```
超级管理程序保护的代码完整性
确保只有经过签名的代码才能在内核中执行
绕过方法：利用已签名的合法驱动、BYOVD（自带漏洞驱动）
```

### CET（Control-flow Enforcement Technology）
```
Intel 的控制流保护技术
防止 ROP/JOP 攻击
绕过方法：利用未启用 CET 的代码路径
```

### ETW（Event Tracing for Windows）
```
Windows 事件追踪，反用挂用它监控 API 调用
绕过方法：修补 ETW 函数、修改 ETW Provider 注册
```

## 开发工作流（8 阶段）

```
阶段 0: 侦察
  - 目标分析（引擎、反外挂、网络架构）
  - 环境搭建（虚拟机、调试器、工具链）

阶段 1: 静态分析
  - 二进制逆向（IDA/Ghidra）
  - 偏移提取（关键数据结构、函数地址）

阶段 2: 动态分析
  - 实时内存验证（只读，不修改）
  - 函数调用跟踪

阶段 3: 概念验证
  - 最小渲染（ESP 框架）
  - 首次内存写入

阶段 4: 核心构建
  - 完整功能实现
  - 性能优化

阶段 5: 加固
  - 检测规避
  - 反调试保护
  - 代码混淆

阶段 6: 测试
  - 多会话验证
  - 反外挂兼容性测试

阶段 7: 维护
  - 游戏更新适配
  - 偏移更新
  - 用户反馈处理
```

## 参考资源

- **game-hacking-guidelines** — 最全参考 https://github.com/RejiDev/game-hacking-guidelines
- **Cat-Driver** — 内核驱动模板 https://github.com/vic4key/Cat-Driver
- **PCILeech** — DMA 工具 https://github.com/ufrisk/pcileech
- **SysWhispers** — 直接系统调用 https://github.com/jthuraisamy/SysWhispers
- **libmem** — 游戏黑客库 https://github.com/rdbo/libmem
- **Interception** — 内核输入驱动 https://github.com/oblitum/Interception
