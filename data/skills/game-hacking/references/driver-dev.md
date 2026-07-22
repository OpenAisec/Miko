# 驱动级开发详解 (Driver Development)

## 目录

1. [驱动开发概述](#驱动开发概述)
2. [环境搭建](#环境搭建)
3. [WDF 驱动基础](#wdf-驱动基础)
4. [内核内存读写](#内核内存读写)
5. [隐藏技术](#隐藏技术)
6. [内核通信](#内核通信)
7. [反检测与对抗](#反检测与对抗)
8. [实战案例](#实战案例)

---

## 驱动开发概述

内核驱动运行在 Ring 0（最高权限），可以：

- 读写任意进程内存（绕过用户态保护）
- 隐藏进程、模块、注册表项
- 拦截系统调用
- 绕过反调试检测
- 直接操作硬件

### 驱动类型

| 类型 | 特点 | 适用场景 |
|------|------|----------|
| WDM | 传统驱动模型 | 底层控制 |
| WDF | 现代驱动框架 | 推荐使用 |
| 文件系统驱动 | 过滤文件操作 | 文件隐藏 |
| 网络驱动 | 过滤网络包 | 协议分析 |

### 法律与风险

```
⚠️ 警告：
- 驱动开发涉及系统底层，错误的代码可能导致蓝屏
- 加载未签名驱动需要禁用驱动签名验证
- 部分反外挂系统会检测驱动加载
- 请确保仅在合法授权的环境中使用
```

---

## 环境搭建

### 工具安装

```
1. 安装 Visual Studio（含 C++ 桌面开发）
2. 安装 Windows Driver Kit (WDK)
   - 下载: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
3. 配置测试环境（推荐使用虚拟机）
   - VMware / VirtualBox
   - 安装 Windows 10/11
   - 启用测试签名模式
```

### 测试签名模式

```powershell
# 以管理员身份运行
bcdedit /set testsigning on
# 重启后生效

# 或者使用禁用驱动签名强制模式（临时）
# 启动时按 F8 → 禁用驱动程序签名强制
```

### 编译驱动

```
Visual Studio → 新建项目 → Kernel Mode Driver (KMDF)
配置:
- 平台: x64
- 配置: Release
- WDK 版本: 最新
```

---

## WDF 驱动基础

### 基本框架

```c
#include <ntddk.h>
#include <wdf.h>

// 驱动卸载回调
VOID DriverUnload(_In_ WDFDRIVER Driver) {
    UNREFERENCED_PARAMETER(Driver);
    KdPrint(("Driver unloaded\n"));
}

// 驱动入口
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    
    KdPrint(("Driver loaded\n"));
    
    // 初始化驱动配置
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = DriverUnload;
    
    // 创建驱动对象
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE
    );
    
    if (!NT_SUCCESS(status)) {
        KdPrint(("WdfDriverCreate failed: 0x%X\n", status));
        return status;
    }
    
    // 创建设备对象
    WDFDEVICE device;
    WDF_DEVICE_CONFIG device_config;
    WDF_DEVICE_CONFIG_INIT(&device_config, WDF_NO_EVENT_CALLBACK);
    
    UNICODE_STRING device_name;
    RtlInitUnicodeString(&device_name, L"\\Device\\GameHelper");
    
    PWDFDEVICE_INIT device_init = WdfControlDeviceInitAllocate(
        WdfGetDriver(), &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    
    WdfDeviceInitAssignName(device_init, &device_name);
    
    status = WdfDeviceCreate(&device_init, WDF_NO_OBJECT_ATTRIBUTES, &device);
    
    if (!NT_SUCCESS(status)) {
        KdPrint(("WdfDeviceCreate failed: 0x%X\n", status));
        return status;
    }
    
    // 创建符号链接（用户态可见）
    UNICODE_STRING sym_link;
    RtlInitUnicodeString(&sym_link, L"\\DosDevices\\GameHelper");
    WdfDeviceCreateSymbolicLink(device, &sym_link);
    
    return STATUS_SUCCESS;
}
```

---

## 内核内存读写

### MmCopyVirtualMemory

```c
// 跨进程内存读取
NTSTATUS kernel_read_memory(
    PEPROCESS source_process,
    PVOID source_address,
    PVOID target_buffer,
    SIZE_T size
) {
    SIZE_T bytes_read = 0;
    NTSTATUS status = MmCopyVirtualMemory(
        source_process,     // 源进程
        source_address,     // 源地址
        PsGetCurrentProcess(),  // 当前进程（驱动）
        target_buffer,      // 目标缓冲区
        size,               // 大小
        KernelMode,
        &bytes_read
    );
    return status;
}

// 跨进程内存写入
NTSTATUS kernel_write_memory(
    PEPROCESS target_process,
    PVOID target_address,
    PVOID source_buffer,
    SIZE_T size
) {
    SIZE_T bytes_written = 0;
    NTSTATUS status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),  // 当前进程（驱动）
        source_buffer,          // 源缓冲区
        target_process,         // 目标进程
        target_address,         // 目标地址
        size,
        KernelMode,
        &bytes_written
    );
    return status;
}
```

### MDL 方式

```c
// 使用 MDL 映射目标进程内存
PVOID map_memory_mdl(PEPROCESS process, PVOID address, SIZE_T size) {
    PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
    if (!mdl) return NULL;
    
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return NULL;
    }
    
    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    
    return mapped;  // 使用后需要 MmUnmapLockedPages 和 IoFreeMdl
}
```

### 辅助函数封装

```c
// 进程名 → PEPROCESS
PEPROCESS get_process_by_name(const wchar_t* process_name) {
    PEPROCESS process = NULL;
    
    for (ULONG pid = 0; pid < 100000; pid += 4) {
        PEPROCESS ep;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &ep))) {
            UCHAR* image_name = PsGetProcessImageFileName(ep);
            wchar_t name[16];
            // 转换并比较
            if (wcsstr(process_name, name)) {
                process = ep;
                ObDereferenceObject(ep);
                break;
            }
            ObDereferenceObject(ep);
        }
    }
    return process;
}

// 获取模块基址
ULONG_PTR get_module_base(PEPROCESS process, const wchar_t* module_name) {
    // 遍历 PEB → Ldr → InLoadOrderModuleList
    // ... 实现略
}
```

---

## 隐藏技术

### 进程隐藏

```c
// 从活动进程链表中摘除
void hide_process(PEPROCESS process) {
    // 获取进程的 LIST_ENTRY
    PLIST_ENTRY active_process_link = (PLIST_ENTRY)(
        (PUCHAR)process + active_process_links_offset);
    
    // 从双向链表中移除
    active_process_link->Blink->Flink = active_process_link->Flink;
    active_process_link->Flink->Blink = active_process_link->Blink;
    
    // 使自引用，防止遍历时出错
    active_process_link->Flink = active_process_link;
    active_process_link->Blink = active_process_link;
}
```

### 模块隐藏

```c
// 从 PEB 模块链表中摘除
void hide_module(PEPROCESS process, const wchar_t* module_name) {
    // 获取 PEB
    PPEB peb = PsGetProcessPeb(process);
    if (!peb) return;
    
    // 遍历 InLoadOrderModuleList
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;
    
    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(
            entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        if (module->BaseDllName.Buffer && 
            wcsstr(module->BaseDllName.Buffer, module_name)) {
            // 从链表中移除
            entry->Blink->Flink = entry->Flink;
            entry->Flink->Blink = entry->Blink;
            break;
        }
        entry = entry->Flink;
    }
}
```

### 注册表隐藏

```c
// Hook 注册表查询，过滤特定键值
NTSTATUS hook_RegQueryValueExW(...) {
    // 调用原始函数
    NTSTATUS status = original_RegQueryValueExW(...);
    
    // 如果查询的是我们要隐藏的键
    if (wcsstr(value_name, L"GameHelper")) {
        return STATUS_NOT_FOUND;
    }
    
    return status;
}
```

---

## 内核通信

### IOCTL 通信

```c
// 定义 IOCTL 控制码
#define IOCTL_READ_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 通信结构体
typedef struct _MEMORY_REQUEST {
    ULONG pid;
    ULONG_PTR address;
    ULONG_PTR buffer;
    SIZE_T size;
} MEMORY_REQUEST, *PMEMORY_REQUEST;

// IOCTL 处理函数
NTSTATUS device_control(
    WDFDEVICE Device,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
) {
    UNREFERENCED_PARAMETER(Device);
    
    NTSTATUS status = STATUS_SUCCESS;
    size_t bytes_returned = 0;
    
    switch (IoControlCode) {
        case IOCTL_READ_MEMORY: {
            PMEMORY_REQUEST req;
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(MEMORY_REQUEST), 
                                                    &req, NULL);
            if (!NT_SUCCESS(status)) break;
            
            PEPROCESS process;
            status = PsLookupProcessByProcessId((HANDLE)req->pid, &process);
            if (!NT_SUCCESS(status)) break;
            
            PVOID output_buf;
            WdfRequestRetrieveOutputBuffer(Request, req->size, &output_buf, NULL);
            
            status = kernel_read_memory(process, (PVOID)req->address, 
                                         output_buf, req->size);
            bytes_returned = req->size;
            
            ObDereferenceObject(process);
            break;
        }
        
        case IOCTL_WRITE_MEMORY: {
            PMEMORY_REQUEST req;
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(MEMORY_REQUEST),
                                                    &req, NULL);
            if (!NT_SUCCESS(status)) break;
            
            PEPROCESS process;
            status = PsLookupProcessByProcessId((HANDLE)req->pid, &process);
            if (!NT_SUCCESS(status)) break;
            
            status = kernel_write_memory(process, (PVOID)req->address,
                                          (PVOID)req->buffer, req->size);
            
            ObDereferenceObject(process);
            break;
        }
    }
    
    WdfRequestCompleteWithInformation(Request, status, bytes_returned);
    return status;
}
```

### 用户态通信代码

```c
#include <windows.h>
#include <winioctl.h>

#define IOCTL_READ_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _MEMORY_REQUEST {
    ULONG pid;
    ULONG_PTR address;
    ULONG_PTR buffer;
    SIZE_T size;
} MEMORY_REQUEST;

HANDLE open_driver() {
    return CreateFileA("\\\\.\\GameHelper", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
}

BOOL driver_read_memory(HANDLE hDriver, ULONG pid, ULONG_PTR address, 
                         PVOID buffer, SIZE_T size) {
    MEMORY_REQUEST req = { pid, address, 0, size };
    DWORD bytes_returned;
    return DeviceIoControl(hDriver, IOCTL_READ_MEMORY, &req, sizeof(req),
        buffer, size, &bytes_returned, NULL);
}

BOOL driver_write_memory(HANDLE hDriver, ULONG pid, ULONG_PTR address,
                          PVOID buffer, SIZE_T size) {
    MEMORY_REQUEST req = { pid, address, (ULONG_PTR)buffer, size };
    DWORD bytes_returned;
    return DeviceIoControl(hDriver, IOCTL_WRITE_MEMORY, &req, sizeof(req),
        NULL, 0, &bytes_returned, NULL);
}
```

---

## 反检测与对抗

### 常见检测手段

```
1. 驱动签名检测 — 检查加载的驱动是否有有效签名
2. 驱动对象枚举 — 遍历驱动链表检测异常驱动
3. 内存完整性校验 — 检查关键内存区域是否被修改
4. 调试寄存器检测 — 检查 DR0-DR7 是否被设置
5. 回调函数检测 — 检查系统回调是否被 Hook
```

### 对抗方法

```
1. 使用签名证书签名驱动
2. 清理驱动对象链表中的痕迹
3. 使用硬件断点而非软件断点
4. 清理回调注册记录
5. 使用未导出的内核 API（需要动态获取地址）
```

```c
// 动态获取未导出函数
PVOID get_kernel_function(const char* function_name) {
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ntoskrnl.exe");
    PVOID ntoskrnl = MmGetSystemRoutineAddress(&name);
    
    // 需要通过特征码搜索
    // 或者使用 pdb 符号文件
    return NULL;  // 实现略
}
```

---

## 实战案例

### 案例：驱动级内存读写工具

```
1. 编写 WDF 驱动，实现 IOCTL 读写接口
2. 用户态程序通过 DeviceIoControl 通信
3. 注入用户态 DLL，通过驱动读写游戏内存
4. 绕过游戏的用户态保护检测
```

### 案例：隐藏辅助进程

```
1. 驱动获取辅助进程的 EPROCESS
2. 从活动进程链表中摘除
3. 从 PEB 链表中摘除相关模块
4. 进程管理器中不可见
```
